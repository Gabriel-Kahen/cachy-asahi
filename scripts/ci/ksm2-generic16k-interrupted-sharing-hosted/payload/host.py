#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite actual QEMU consumer of an owned source-preserving boot-media lease."""
import argparse,fcntl,json,os,re,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def qemu(image,boot,data,nonce,clock):
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append','console=ttyAMA0 root=/dev/vda rw rootwait init=/init-ksm2 arm64.nomops caa_ksm2_vm='+nonce+' caa_clock_ns='+str(clock),'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot','-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data','-serial','stdio']

SHIM_SOURCE_PIN={'bytes': 733, 'sha256': '3d0d1378a4281c47ec83a721e260c22f4aece74d16126e1173077f62bc6b1e20'}

def ldconfig_protocol(value):
 import re
 p=value['ldconfig_policy'];nonce=value['nonce'];C.need(re.fullmatch('[a-f0-9]{32}',nonce or''),'exact private helper nonce')
 fields={'status','helper','deny_errno','other_execv','native_libalpm','source','compiled','compiler_argv','library','environment_scope','commands','helper_exit','production_policy','denial_marker'}
 C.need(type(p)is dict and set(p)==fields,'closed native helper-policy receipt')
 C.need((p['status'],p['helper'],p['deny_errno'],p['other_execv'],p['environment_scope'],p['helper_exit'],p['production_policy'])==('EXPLICIT_BUILTIN_LDCONFIG_EXEC_DENIAL_NOT_HELPER_SUCCESS','/usr/bin/ldconfig','EPERM','RTLD_NEXT_UNCHANGED','ONLY_EXACT_SIGNED_INSTALL_AND_REMOVE_PACMAN_COMMANDS','NOT_OBSERVED','NOT_INSTALLED'),'explicit finite helper-exec denial, no helper-success credit')
 marker=C.pin(b'CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\n');C.need(p['denial_marker']==marker,'exact source-owned exec-denial marker')
 C.need(p['native_libalpm']==dict(bytes=330416,sha256='94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902')and p['source']==SHIM_SOURCE_PIN,'same original signed native ALPM and embedded complete policy C')
 directory='/tmp/ksm2-ldconfig-policy-'+nonce;library=directory+'/policy.so';source=directory+'/policy.c'
 argv=['/usr/bin/cc','-std=c11','-O2','-fPIC','-shared','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-Wl,--no-undefined','-Wl,-z,max-page-size=16384,-z,common-page-size=16384','-o',library,source,'-ldl']
 C.need(p['library']==library and p['compiler_argv']==argv,'whole finite native compiler argv and private policy paths')
 def bounded_pin(row):
  C.need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=1024**2 and re.fullmatch('[a-f0-9]{64}',row['sha256']or''),'bounded source-recorded compiled-object pin')
 def command_row(row,limit):
  fields={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
  C.need(type(row)is dict and set(row)==fields and type(row['argv'])is list and all(type(x)is str for x in row['argv']),'exact original command supervisor record')
  C.need(type(row['exit_code'])is int and row['exit_code']==0 and row['group_absence_verified']is True and type(row['time_limit'])in(int,float)and 0<row['time_limit']<=limit and type(row['seconds'])in(int,float)and 0<=row['seconds']<=row['time_limit']+6 and type(row['output_limit'])is int and row['output_limit']==128*1024,'natural finite original command retirement')
  for name in('stdout','stderr'):C.need(type(row[name+'_bytes'])is int and 0<=row[name+'_bytes']<=128*1024 and type(row[name+'_sha256'])is str and re.fullmatch('[a-f0-9]{64}',row[name+'_sha256']),'complete bounded command stream identity')
  C.need(row['stdout_bytes']+row['stderr_bytes']<=128*1024,'combined original command stream cap')
 bounded_pin(p['compiled']);rows=value['commands'];compiled=[(i,row)for i,row in enumerate(rows)if row['argv']==argv];C.need(len(compiled)==1,'one actual supervised native policy compilation')
 compile_index,compile_row=compiled[0];command_row(compile_row,35);C.need(compile_row['exit_code']==0 and compile_row['group_absence_verified']is True and 0<compile_row['time_limit']<=35 and compile_row['output_limit']==128*1024,'native policy compiler original command retirement/budget')
 prefix=['/usr/bin/pacman','--config','/tmp/apps-cache-pacman.conf','--noconfirm','--noscriptlet'];archive='/tmp/ksm2-install-'+nonce+'/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz';commands=[prefix+['-U',archive],prefix+['-R',C.PACKAGE]]
 env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root',LD_PRELOAD=library);C.need(type(p['commands'])is list and len(p['commands'])==2,'only original signed install/remove receive private preload')
 positions=[]
 for receipt,wanted in zip(p['commands'],commands):
  C.need(type(receipt)is dict and set(receipt)=={'argv','environment','helper_denial_capture'}and receipt['argv']==wanted and receipt['environment']==C.pin(C.encoded(env)),'exact signed selected CLI and complete finite environment join')
  selected=[(i,row)for i,row in enumerate(rows)if row['argv']==wanted];C.need(len(selected)==1,'one matching original signed transaction command');index,row=selected[0];command_row(row,90);positions.append(index)
  C.need(row['exit_code']==0 and row['group_absence_verified']is True and 0<row['time_limit']<=90 and row['output_limit']==128*1024,'original normal signed transaction exit/retirement/budget')
  captured=receipt['helper_denial_capture'];C.need(type(captured)is dict and set(captured)=={'marker','stdout','stderr','status'}and captured['marker']==marker and captured['status']=='HELPER_EXEC_DENIED_EPERM_NOT_HELPER_SUCCESS','source-enforced actual helper-denial capture; no helper-success result')
  for name in('stdout','stderr'):C.need(captured[name]==dict(bytes=row[name+'_bytes'],sha256=row[name+'_sha256']),'whole captured denial stream joins original command record')
 C.need(compile_index<positions[0]<positions[1],'actual compiler precedes signed install then remove')
 return value

def protocol(raw,s,kernel,clock):
 C.need(type(raw)is bytes and len(raw)<=C.CAP and b'KSM2_VM_ERROR 'not in raw,'bounded actual UART without guest failure');prefix=('KSM2_VM '+s['nonce']+' ').encode();lines=[v for v in raw.splitlines()if v.startswith(b'KSM2_VM ')];C.need(len(lines)==3 and all(v.startswith(prefix)for v in lines),'three exact nonce boot/result/retirement frames')
 boot,v,end=[C.decode(line[len(prefix):])for line in lines]
 sharing=C.load('_ksm_sharing_protocol',C.HERE/'sharing.py');sharing.validate(v['sharing'],s['nonce']);C.need(v['memory_sharing']=='PASS_OWNED_VM_ANONYMOUS_SHARING_UNMERGE','explicit separate anonymous sharing scope');sharing.command_join(v['sharing'],v['commands'])
 interrupted=C.load('_ksm_interrupted_protocol',C.HERE/'interrupted.py');interrupted.validate(v['sharing_interruption'],s['nonce']);C.need(v['sharing_interruption']['owner_parent']==v['sharing']['parent'],'same original guest worker owns both sharing commands');interrupted.command_join(v['sharing_interruption'],v['commands'])
 C.need(boot==dict(event='boot',architecture='aarch64',page_size=16384,kernel=kernel['release'],kernel_profile_sha256=C.sha(C.encoded(kernel)),clock_seed_ns=clock,nofile=8192),'actual fresh16K boot/profile/clock join')
 C.need(v['actual_source']==s['VM_source']and v['actual_ref']==s['VM_ref']and v['actual_run']==s['VM_run']and v['event']=='result'and v['status']=='PASS_INSTALLED_KSM2_GENERIC16K_GUEST_ONLY'and v['nonce']==s['nonce']and v['page_size']==16384 and v['kernel']==kernel and v['package_counts']==[574,575,574]and v['hardware']=='NOT_RUN'and v['release']=='NOT_ADMITTED','actual complete installed generic16K scope')
 C.need(end==dict(event='exit',status='PASS',cleanup='PASS_OWNED_MOUNTS_RETIRED'),'actual PID1 owned mount retirement after worker')
 C.need(v['isolation']['after']==dict(mask=0x800400fb,nnp=1,inh=0,amb=0)and v['isolation']['uid']==v['isolation']['gid']==0 and v['isolation']['groups']==[]and v['isolation']['seccomp']==2,'exact source-held nine-cap no-SYS_ADMIN worker')
 C.need(v['source_capabilities_before']==v['source_capabilities_after']==s['capabilities_sha256']and v['boot574_nodes_sha256']==s['source_nodes_sha256'],'complete original574 private boot and capability map joins')
 C.need(v['complete_post_removal_map']=='EXACT_ORIGINAL_NODES_EXCEPT_PINNED_EXISTING_ALPM_LOG_APPEND'and v['ALPM_log']['scope']=='PRIVATE_CONTENT_NOT_EXPORTED_APPEND_ONLY','whole post-removal persistent observation required')
 scalar=v['scalar'];C.need(scalar['status']=='PASS_REAL_SYSFS_SCALAR_RESTORE_AND_FOREIGN_EDIT_REFUSAL'and type(scalar['baseline'])is int and scalar['baseline']in(0,1)and scalar['desired']==1-scalar['baseline']and scalar['state_retirement']=='EXACT_OWN_UNDONE_RECORDS_ONLY'and scalar['unmerge']=='NOT_RUN_NEVER2'and scalar['interruption']=='NOT_RUN_NO_SHIPPED_DETERMINISTIC_HOOK','actual scalar restoration and finite scope')
 actions=['preview','apply','inspect','undo','inspect']+['preview','apply','inspect','undo','undo','inspect'];events=scalar['events'];C.need(len(events)==len(actions),'all eleven required real helper observations')
 for n,(event,action)in enumerate(zip(events,actions)):
  case=0 if n<5 else 1;name='vm-'+s['nonce'][:16]+('-restore'if case==0 else'-conflict');refused=n==8
  C.need(event['action']==action and event['name']==name and event['exit']==(1 if refused else 0)and event['actual']in(0,1),'exact real helper action/name/result scope')
  if refused:C.need(event['actual']==scalar['baseline']and event['result']['status']=='REFUSED','actual foreign-edit refusal')
  else:
   r=event['result'];C.need(r['name']==name and r['baseline']==scalar['baseline']and r['desired']==scalar['desired'],'same immutable baseline/desired plan')
   if action=='preview':C.need(r['phase']=='PLANNED'and r['kernel_write']is False and event['actual']==scalar['baseline'],'read-only preview')
   elif action=='apply':C.need(r['phase']=='APPLIED'and r['kernel_write']is True and r['current']==event['actual']==scalar['desired'],'actual sysfs apply')
   elif action=='undo':C.need(r['phase']=='UNDONE'and r['current']==event['actual']==scalar['baseline'],'actual original scalar undo')
   else:C.need(r['phase']==('APPLIED'if n in(2,7)else'UNDONE')and r['intent_uncertain']is False and r['current']==event['actual']==(scalar['desired']if n in(2,7)else scalar['baseline']),'independent actual scalar observation')
 for row in v['commands']:C.need(row['exit_code']in(0,1)and row['group_absence_verified']is True and 0<row['time_limit']<=90 and row['output_limit']==128*1024,'natural bounded installed command/group retirement')
 C.need(v['process_retirement']['status']=='ONLY_PID1_AND_OBSERVED_KERNEL_THREADS'and type(v['process_retirement']['kernel_threads'])is int and 0<=v['process_retirement']['kernel_threads']<=512,'no remaining non-kernel guest processes before mount retirement')
 worker=v['worker'];C.need(worker['argv']==['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']and worker['exit_code']==0 and worker['group_absence_verified']is True and worker['time_limit']==C.SHARED_SECONDS and worker['output_limit']==512*1024,'exact direct worker complete retirement')
 return ldconfig_protocol(v)

def retire_media(directory,lease,identities,row):
 C.need(row['group_absence_verified']is True,'retain media while QEMU group absence unknown')
 directory=Path(directory);C.need(set(p.name for p in directory.iterdir())=={'boot.raw','data.raw','prepared.json','ksm2-media.json','stage-owner.json'},'only owned prepared media may retire')
 for name,identity in identities.items():
  p=directory/name;st=p.lstat();C.need([st.st_dev,st.st_ino,st.st_uid,st.st_size]==identity and st.st_nlink==1 and stat.S_ISREG(st.st_mode),'same owned media inode after QEMU')
 for name in('prepared.json','ksm2-media.json','stage-owner.json'):C.need(C.row(directory/name)==lease['metadata_files'][name],'same owned metadata receipt')
 for p in directory.iterdir():p.unlink()
 directory.rmdir();C.need(not directory.exists(),'all owned disks removed after QEMU group retirement');return 'PASS_EXACT_OWNED_MEDIA_REMOVED_AFTER_QEMU_GROUP_ABSENCE'

def run(a):
 s=C.decode(C.read(a.selection))
 if s.get('media')is None:
  C.native_gate(s,a.inputs);C.actual_environment(s);K=C.load('_ksm_early_kernel_gate',C.HERE/'kernel_input.py');K.imported(s,a.inputs);s=dict(s,media=dict(path='ksm2-media.json',**C.pin(C.read(a.media/'ksm2-media.json',2*1024**2))))
 C.gate(s,a.inputs);C.actual_environment(s) # Before outputs, kernel, media or QEMU.
 C.support();C.source_check();C.need(re.fullmatch('[0-9a-f]{32}',s.get('nonce')or''),'fresh nonce');C.need(not a.output.exists()and a.output.parent.is_dir()and not any(p.is_symlink()for p in(a.output,*a.output.parents)),'fresh owned output only')
 K=C.load('_ksm_kernel_input',C.HERE/'kernel_input.py');kernel,receipt,image,config=K.imported(s,a.inputs);C.need(s['kernel']==kernel,'media selection and actual imported kernel profile differ')
 lease=C.decode(C.checked(a.media,s['media'],2*1024**2));C.need(lease['status']=='PREPARED_ORIGINAL574_KSM2_OWNED_MEDIA'and lease['nonce']==s['nonce']and lease['original574_preserved']is True and lease['staging_retired']is True and lease['source_caps_restoration']=='SOURCE_STAGE_RESTORED_GUEST_REQUIRES_EXACT_MAP'and lease['private_maps']=='KEPT_IN_READONLY_GUEST_INPUTS','strict source-preserving prepared media lease required')
 C.need(set(lease['files'])=={'boot.raw','data.raw'}and lease['files']['boot.raw']['bytes']==16*1024**3 and lease['files']['data.raw']['bytes']==24*1024**3,'fixed complete disk media roles')
 producer=C.decode(C.read(a.producer_output/'report.json'));C.need(C.pin(C.encoded(producer))==C.pin(C.encoded(C.decode(C.checked(a.inputs,s['producer_report'],2*1024**2)))),'original producer output joins exact selected report');preparation=C.decode(C.read(a.prepare_work/'preparation-result.json'));C.need(preparation['nonce']==s['nonce']and preparation['actor_absent']is True and preparation['prepared']==C.row(a.media/'ksm2-media.json'),'same-nonce preparer retired before boot')
 identities={}
 for name,p in lease['files'].items():
  file=a.media/name;st=file.lstat();C.need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and not(st.st_mode&0o022),'owned ordinary disk file')
  with file.open('rb')as stream:digest=__import__('hashlib').file_digest(stream,'sha256').hexdigest()
  C.need(dict(bytes=st.st_size,sha256=digest)==p,'complete sealed disk bytes');identities[name]=[st.st_dev,st.st_ino,st.st_uid,st.st_size]
 guest_s=dict(s,media=None,capabilities_sha256=lease['capabilities_sha256']);C.need(C.pin(C.encoded(guest_s))==lease['selection_pin'],'exact sealed execution selection, no circular media authority');guest_s['source_nodes_sha256']=lease['source_nodes_sha256']
 lease['metadata_files']={name:C.row(a.media/name)for name in('prepared.json','ksm2-media.json','stage-owner.json')}
 a.output.mkdir(mode=0o700);kernel_dir=a.output/'kernel';kernel_dir.mkdir(mode=0o700);copied={}
 for name,path,pin in(('Image',image,kernel['Image']),('config',config,kernel['config'])):
  raw=C.read(path,256*1024**2 if name=='Image'else 262144);C.need(C.pin(raw)==pin,'exact kernel DATA before fresh owned materialization');target=kernel_dir/name;target.write_bytes(raw);target.chmod(0o600);v=target.stat();copied[name]=dict(pin=pin,identity=[v.st_dev,v.st_ino,v.st_uid]);C.need(C.row(target)==pin,'whole copied kernel DATA')
 image=kernel_dir/'Image';R=C.load('_ksm_vm_original_supervisor',C.HERE/'borrowed/runtime.py');clock=time.time_ns();argv=qemu(image,a.media/'boot.raw',a.media/'data.raw',s['nonce'],clock);deadline=time.monotonic()+C.SHARED_SECONDS
 row,out,err,error=R.run_command(argv,a.output,dict(PATH='/usr/bin:/bin',HOME=str(a.output),LANG='C'),C.SHARED_SECONDS,C.CAP)
 for name,raw in [('uart.log',out),('qemu.stderr',err),('qemu.json',C.encoded(row))]:(a.output/name).write_bytes(raw)
 C.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True and time.monotonic()<=deadline+6,'natural QEMU/direct-group retirement under original full5743000 envelope')
 result=protocol(out,guest_s,kernel,clock);C.native_gate(s,a.inputs);K.imported(s,a.inputs) # Fresh complete original input recheck after actor retirement.
 for name,held in copied.items():
  target=kernel_dir/name;v=target.lstat();C.need([v.st_dev,v.st_ino,v.st_uid]==held['identity']and C.row(target)==held['pin'],'same owned kernel inode/bytes after QEMU');target.unlink()
 kernel_dir.rmdir();C.need(not kernel_dir.exists(),'copied kernel DATA retired after QEMU group absence');retirement=retire_media(a.media,lease,identities,row);original=C.load('_ksm_original574_cleanup',C.HERE/'borrowed/maintained_desktop574.py');v=a.producer_output.lstat();C.need(stat.S_ISDIR(v.st_mode)and v.st_uid==os.getuid()and stat.S_IMODE(v.st_mode)==0o700,'original producer private directory lease');lease_fd=os.open(a.producer_output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);saved=dict(os.environ)
 try:
  fcntl.flock(lease_fd,fcntl.LOCK_EX|fcntl.LOCK_NB);C.need(C.decode(C.read(a.producer_output/'report.json'))==producer,'same original producer report under exclusive lease')
  os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(a.prepare_work),DOCKER_CONFIG=str(a.prepare_work/'docker-config'));producer_retirement=original.retire_owned(a.producer_output,producer['ownership']['token'],producer)
 finally:os.environ.clear();os.environ.update(saved);os.close(lease_fd)
 C.save(a.output/'producer-retirement.json',producer_retirement);C.need(producer_retirement['status']=='PASS'and producer_retirement['image']['absence_verified']is True and producer_retirement['probe']['absence_verified']is True,'original producer probe/image retirement after all consumers');P=C.load('_ksm_prepare_retirement',C.HERE/'prepare_driver.py');work_retirement=P.retire_work(a.prepare_work,s,row,a.output);result.update(natural_qemu=row,kernel_build=C.pin(C.encoded(receipt)),media_retirement=retirement,preparation_work_retirement=work_retirement,producer_retirement=producer_retirement,Root_acceptance='NOT_GRANTED');(a.output/'guest-result.json').write_bytes(C.encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('selection','inputs','media','prepare-work','producer-output','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();r=run(a);print(json.dumps({k:r[k]for k in('status','Root_acceptance','media_retirement')},sort_keys=True))
