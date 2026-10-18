#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual installed KSM2 sysfs lifecycle. Entry refuses outside owned16K PID1."""
import ctypes,fcntl,json,os,resource,stat,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
COMMAND='/usr/bin/cachy-asahi-ksm-experiment';STORE=Path('/var/lib/cachy-asahi-ksm-experiments');RUN=Path('/sys/kernel/mm/ksm/run')

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
 I=C.load('_ksm_vm_installed','/source/borrowed/installed.py');L=C.load('_ksm_vm_preserve','/source/borrowed/lifecycle.py');driver=C.load('_ksm_vm_database','/source/borrowed/root_upgrade.py');runtime=C.load('_ksm_vm_supervision','/source/borrowed/runtime.py')
 rows=[];deadline=time.monotonic()+C.SHARED_SECONDS
 def command(argv,expected=0,seconds=35):
  remaining=min(seconds,deadline-time.monotonic());C.need(remaining>0,'whole VM lifecycle deadline')
  r,out,err,error=runtime.run_command(argv,Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root'),remaining,128*1024);rows.append(r)
  C.need(error is None and r['exit_code']==expected and r['group_absence_verified']is True,'natural direct installed command/group retirement');
  if expected==1:C.need(out==b''and err==b'KSM experiment refused: KSM changed; conflict preserved\n','exact installed foreign-edit refusal')
  return out.decode() if expected==0 else C.encoded(dict(status='REFUSED',exit=expected,stderr_sha256=r['stderr_sha256'])).decode()
 L.command=lambda argv,expected=0,timeout=35:command(argv,expected,timeout)
 base=C.decode(C.read('/source/borrowed/base574.json'));C.need(len(base)==574 and L.inventory()==base and C.PACKAGE not in base,'exact original574 and KSM absent')
 log=Path('/var/log/pacman.log');log_before=C.read(log,16*1024**2);C.need(expected.get('var/log/pacman.log',{}).get('sha256')==C.sha(log_before)and log.lstat().st_nlink==1,'existing ordinary original ALPM log')
 before=I.base_state(L,driver);base_pin=I.preserve_base(L,before);trust=dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d')));users=L.snapshot(Path('/home'))
 def preserve():
  C.need(I.preserve_base(L,before)==base_pin and trust==dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d')))and users==L.snapshot(Path('/home')),'all original574 rawDB/payload/user/system trust preserved')
 _,index=C.native_gate(s,'/inputs',root='/source');public='/inputs/'+index['files']['public_key']['path'];pacman=I.pacman(L,index['signer'],public=public);staged=Path('/tmp')/('ksm2-install-'+s['nonce']);C.need(not os.path.lexists(staged),'fresh private signed package staging');staged.mkdir(mode=0o700);archive=staged/Path(index['files']['a']['path']).name;signature=Path(str(archive)+'.sig');archive.write_bytes(C.checked('/inputs',index['files']['a']));signature.write_bytes(C.checked('/inputs',index['files']['signature']));archive.chmod(0o600);signature.chmod(0o600);staged_pins={p.name:C.row(p)for p in(archive,signature)};C.need(C.row(archive)=={k:index['files']['a'][k]for k in('bytes','sha256')}and C.row(signature)=={k:index['files']['signature'][k]for k in('bytes','sha256')},'exact original signed archive copied to own tmp staging only')
 command(pacman+['-U',str(archive)],seconds=90);C.need(L.inventory()==base|{C.PACKAGE:C.VERSION},'actual ordinary signed575 installation');I.payloads(L,{C.PACKAGE:dict(payload=index['product']['builds'][0]['payload'])});preserve()
 C.need(C.sha(C.read(COMMAND))==index['product']['builds'][0]['payload']['usr/bin/cachy-asahi-ksm-experiment']['sha256'],'exact installed helper bytes')
 def call(argv,expected=0,seconds=15):return C.decode(command(argv,expected,seconds).encode())
 result=scalar_case(s,call);preserve();command(pacman+['-R',C.PACKAGE],seconds=90);C.need(L.inventory()==base and not os.path.lexists(STORE),'original574 restored and own experiment store retired');preserve();last_nodes,last_mapping,*_=M.source_nodes('/source');C.need(last_mapping==held_mapping,'all persistent file capabilities preserved after removal');log_after=C.read(log,16*1024**2);C.need(log_after.startswith(log_before),'original ALPM log prefix preserved');permitted=dict(expected);permitted['var/log/pacman.log']=dict(expected['var/log/pacman.log'],bytes=len(log_after),sha256=C.sha(log_after));C.need(last_nodes==permitted,'complete post-removal node/hash/hardlink map; only existing ALPM log append permitted');command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])
 C.need(set(p.name for p in staged.iterdir())==set(staged_pins),'only own signed staging files');
 for p in staged.iterdir():C.need(C.row(p)==staged_pins[p.name],'held staged signed bytes');p.unlink()
 staged.rmdir();C.need(not staged.exists(),'owned signed staging retired')
 return dict(actual_source=s['VM_source'],actual_ref=s['VM_ref'],actual_run=s['VM_run'],isolation=isolation,source_capabilities_before=C.sha(C.encoded(mapping)),source_capabilities_after=C.sha(C.encoded(last_mapping)),boot574_nodes_sha256=C.sha(C.encoded(expected)),status='PASS_INSTALLED_KSM2_GENERIC16K_GUEST_ONLY',nonce=s['nonce'],page_size=16384,kernel=s['kernel'],scalar=result,base574_preservation_sha256=base_pin,package_counts=[574,575,574],complete_post_removal_map='EXACT_ORIGINAL_NODES_EXCEPT_PINNED_EXISTING_ALPM_LOG_APPEND',ALPM_log=dict(before=C.pin(log_before),after=C.pin(log_after),scope='PRIVATE_CONTENT_NOT_EXPORTED_APPEND_ONLY'),user_and_system_trust='EXACT_PRIVATE_NATIVE_GUARDS',commands=rows,hardware='NOT_RUN',performance='NOT_MEASURED',memory_sharing='NOT_TESTED',release='NOT_ADMITTED')

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
 R=C.load('_ksm_pid1_supervision','/source/borrowed/runtime.py');row,out,err,error=R.run_command(['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),C.SHARED_SECONDS,512*1024)
 Path('/out/worker.stdout').write_bytes(out);Path('/out/worker.stderr').write_bytes(err);C.save('/out/worker.json',row)
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
