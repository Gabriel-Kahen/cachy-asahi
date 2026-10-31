# SPDX-License-Identifier: MIT
"""Owned original-image disk preparation,16K QEMU, bounded original readback."""
import base64,json,os,re,shutil,time
from pathlib import Path
import contract as C
MOUNTS={'/inputs','/runner.py','/upgrade-code','/upgrade-config.json','/upgrade-pair','/upgrade-hook.py','/persistent_scope.py','/setup4.py','/footprint.py','/measurement-source','/out','/measurement','/upgrade-signing'}
RO=MOUNTS-{'/out','/measurement','/upgrade-signing'}

def authorize(a):
 old,held,b=C.gate(a.implementation,a.case);C.own_source(old,a.implementation,a.implementation_revision);C.accepted(old,a.updater_decisions,b)
 # The new VM commit is distinct from its accepted prior updater. Its complete
 # unchanged original closure is joined by the manifest, never a self-reference.
 return kernel(a)

def kernel(a):
 C.need(a.kernel_work.is_absolute() and a.kernel_work.is_dir() and not any(p.is_symlink() for p in (a.kernel_work,*a.kernel_work.parents)),'explicit owned kernel directory')
 r=C.decode(C.read(a.kernel_receipt,65536))
 for n in ('helper','fragment','image','config'):
  p=Path(r[n]['path']);C.need(p.is_relative_to(a.kernel_work) and not any(q.is_symlink() for q in (p,*p.parents)),'kernel receipt path containment')
 K=C.load('kernel_contract',a.implementation/'scripts/ci/managed-gui-generic16k/kernel_contract.py');H=C.load('kernel_helper',a.implementation/'scripts/ci/managed-gui-generic16k/build_kernel.py')
 fragment=a.implementation/'scripts/ci/managed-gui-generic16k/kernel.fragment'
 profile,image,config=K.from_receipt(r,H,C.read(fragment),C.row(a.implementation/'scripts/ci/managed-gui-generic16k/build_kernel.py')['sha256'],C.row(fragment)['sha256'])
 C.need(C.row(r['helper']['path'])=={k:r['helper'][k] for k in ('bytes','sha256')},'copied kernel helper identity')
 C.need(C.row(r['fragment']['path'])=={k:r['fragment'][k] for k in ('bytes','sha256')},'copied kernel fragment identity')
 return profile,image,config

def mounts(argv):
 C.need(argv[:3]==['docker','run','--rm'],'exact original caller Docker argv')
 result={}
 for i,v in enumerate(argv):
  if v!='--mount':continue
  fields=argv[i+1].split(',');values=dict(x.split('=',1) for x in fields if '=' in x)
  dest=values.get('dst');C.need(dest in MOUNTS and dest not in result,'closed original mount roles')
  if dest=='/measurement':C.need(values.get('type')=='volume' and 'volume-nocopy' in fields,'original owned volume');continue
  C.need(values.get('type')=='bind' and set(values)=={'type','src','dst'},'original bind shape')
  path=Path(values['src']);C.need(path.is_absolute() and path.exists() and not any(p.is_symlink() for p in (path,*path.parents)) and ',' not in str(path),'ordinary original bind')
  C.need(('readonly' in fields)==(dest in RO),'original binding authority')
  result[dest]=dict(source=str(path),readonly=dest in RO)
 C.need(set(result)==MOUNTS-{'/measurement'},'complete original mount set')
 caps=tuple(v.split('=',1)[1] for v in argv if v.startswith('--cap-add='))
 C.need(set(caps)=={'CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID','SYS_CHROOT','SETFCAP','KILL','FSETID'} and len(caps)==9,'unchanged native nine-cap roles')
 values=[v.removeprefix('--env=') for v in argv]
 env={v.split('=',1)[0]:v.split('=',1)[1] for v in values if v.startswith(('CACHY_ASAHI_COMPOSITION=','CACHY_ASAHI_BOUND_UPDATE='))}
 C.need(set(env)=={'CACHY_ASAHI_COMPOSITION','CACHY_ASAHI_BOUND_UPDATE'} and all(re.fullmatch('[0-9a-f]{32}',v) for v in env.values()),'original independent nonce markers')
 return result,env

def qemu(image,boot,data,epoch):
 C.need(type(epoch)is int and 1700000000<=epoch<2**32,'bounded launcher UTC epoch required')
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append','console=ttyAMA0 root=/dev/vda rw rootwait init=/init-updater16k caa_apps6_update16k=1 arm64.nomops cachy_asahi_updater_epoch='+str(epoch),'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot','-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data','-serial','stdio']

def nomops_readback(raw,selection):
 # Same complete captured UART, no kernel/header/config inference.
 C.need(type(raw)is bytes and len(raw)<=16*1024**2,'bounded complete NOMOPS UART')
 lines=raw.decode('utf8','strict').splitlines()
 expected='console=ttyAMA0 root=/dev/vda rw rootwait init=/init-updater16k caa_apps6_update16k=1 arm64.nomops cachy_asahi_updater_epoch='+str(selection['launcher_epoch_s'])
 command=[line.split('Kernel command line: ',1)[1]for line in lines if 'Kernel command line: 'in line]
 forced=[line for line in lines if re.search(r'ID_AA64ISAR2_EL1\[19:16\]: forced to 0\b',line)]
 C.need(command==[expected]and expected.split().count('arm64.nomops')==1,'one exact source NOMOPS kernel command line')
 C.need(len(forced)==1 and not any('CPU features: detected: Memory Copy and Memory Set instructions'in line for line in lines),'actual kernel MOPS field forced zero and never enabled')
 return dict(status='SOURCE_ENFORCED_NOMOPS_UART_READBACK_ONLY',kernel_command_line=command[0],field='ID_AA64ISAR2_EL1.MOPS[19:16]',forced_value=0,enabled_MOPS=False,UART=dict(bytes=len(raw),sha256=C.sha(raw)))

def protocol(raw,selection,verify):
 C.need(len(raw)<=16*1024**2,'bounded original UART')
 prefix=('APPS6_UPDATE16K '+selection['nonce']+' ').encode();lines=[x.rstrip(b'\r') for x in raw.splitlines() if x.startswith(b'APPS6_UPDATE16K ')]
 C.need(len(lines)==3 and all(x.startswith(prefix) for x in lines),'three nonce-bound original guest records')
 boot,result,end=[C.decode(x[len(prefix):]) for x in lines]
 C.need(boot['event']=='boot' and boot['page_size']==16384 and boot['kernel']==selection['kernel']['release'] and boot['architecture']=='aarch64' and boot['kernel_profile_sha256']==C.sha(C.encoded(selection['kernel'])) and boot['nofile']['after']==[8192,8192],'actual16K kernel/profile/descriptor joins')
 clock=boot['clock'];epoch=selection['launcher_epoch_s'];C.need(set(clock)=={'source','before_ns','requested_epoch_s','after_ns'}and clock['source']=='OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY'and clock['requested_epoch_s']==epoch and type(clock['before_ns'])is int and type(clock['after_ns'])is int and epoch*10**9<=clock['after_ns']<(epoch+2)*10**9,'same owned launcher realtime seed and actual PID1 readback')
 C.need(result['event']=='result' and result['status']==C.PASS and result['case']==selection['case'] and result['isolation']['after']==dict(mask=C.MASK,nnp=1,inh=0,amb=0) and result['isolation']['seccomp']==2 and result['isolation']['uid']==result['isolation']['gid']==0 and result['isolation']['groups']==[] and result['child']['exit_code']==0 and result['child']['group_absence_verified'] is True and result['source_capabilities_before']==result['source_capabilities_after']==selection['capabilities_sha256'],'original update child and actual caps retirement')
 C.need(result['elf16k']['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT' and all(type(result['elf16k'][n]['ELFs']) is int and result['elf16k'][n]['ELFs']>0 and re.fullmatch('[0-9a-f]{64}',result['elf16k'][n]['sha256']) for n in ('before','after')),'complete574/604 ELF audit joins')
 verify(result['caller'],selection['case'])
 C.need(end==dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED'),'actual guest mount retirement')
 nomops_readback(raw,selection)
 return result

def boot_witness(raw,selection):
 # Exact wire bytes from the same accepted UART, not reconstructed boot JSON.
 nomops=nomops_readback(raw,selection)
 C.need(type(raw)is bytes and len(raw)<=16*1024**2,'bounded original UART boot witness')
 prefix=('APPS6_UPDATE16K '+selection['nonce']+' ').encode();lines=[];position=0;offsets=[]
 for line in raw.splitlines(keepends=True):
  if line.startswith(b'APPS6_UPDATE16K '):lines.append(line);offsets.append(position)
  position+=len(line)
 C.need(len(lines)==3 and all(line.startswith(prefix)for line in lines),'three same-nonce original UART frames before boot witness')
 line=lines[0];C.need(0<len(line)<=4096 and line.endswith(b'\n'),'bounded complete original boot LINE')
 boot=C.decode(line[len(prefix):].rstrip(b'\r\n'));C.need(boot['event']=='boot'and boot['page_size']==16384 and boot['kernel']==selection['kernel']['release']and boot['architecture']=='aarch64'and boot['kernel_profile_sha256']==C.sha(C.encoded(selection['kernel']))and boot['nofile']['after']==[8192,8192],'same original boot/kernel/profile/descriptor witness')
 clock=boot['clock'];epoch=selection['launcher_epoch_s'];C.need(set(clock)=={'source','before_ns','requested_epoch_s','after_ns'}and clock['source']=='OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY'and type(clock['requested_epoch_s'])is int and clock['requested_epoch_s']==epoch and type(clock['before_ns'])is int and type(clock['after_ns'])is int and epoch*10**9<=clock['after_ns']<(epoch+2)*10**9,'same original clock witness')
 return dict(status='ORIGINAL_BOOT_LINE_SOURCE_CAPTURED_NOT_FULL_UART_EXPORT',nomops_readback=nomops,line=dict(bytes=len(line),sha256=C.sha(line),base64=base64.b64encode(line).decode()),offset=offsets[0],stdout=dict(bytes=len(raw),sha256=C.sha(raw)),membership='SOURCE_ENFORCED_SAME_CAPTURE_NOT_INDEPENDENT_FULL_UART_ATTESTATION')

def snapshot(bindings):
 result={};count=0;total=0
 for dest,b in bindings.items():
  if dest=='/out':continue
  root=Path(b['source']);items=[root,*sorted(root.rglob('*'))] if root.is_dir() else [root]
  for p in items:
   count+=1;C.need(count<=20000 and not p.is_symlink(),'bounded ordinary original input closure')
   info=p.lstat();key=dest+('/'+p.relative_to(root).as_posix() if p!=root else '')
   if p.is_dir():result[key]=dict(type='directory',mode=info.st_mode&0o7777,uid=info.st_uid,gid=info.st_gid)
   else:
    C.need(p.is_file() and info.st_nlink==1 and info.st_size<=1024**3,'ordinary input/private signer file, no live sockets')
    total+=info.st_size;C.need(total<=8*1024**3,'input aggregate bytes');result[key]=dict(type='file',mode=info.st_mode&0o7777,uid=info.st_uid,gid=info.st_gid,**C.row(p))
 return result

def prepare_failure(record,stderr):
 # Failed owned preparation only: exact original stream pin plus bounded tail.
 C.need(record['argv'][-2:]==['/workspace/disk.py','prepare'] and record['exit_code']!=0,'failed prepare diagnostic only')
 C.need(len(stderr)==record['stderr_bytes'] and C.sha(stderr)==record['stderr_sha256'],'original prepare stderr join')
 tail=stderr[-4096:]
 return dict(status='FAILED_PREPARE_STDERR_NOT_ACCEPTANCE',stderr=dict(bytes=len(stderr),sha256=C.sha(stderr),tail_bytes=len(tail),tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(stderr)-len(tail)))

def qemu_failure(record,stdout,stderr,nonce):
 # Diagnostic only: byte/hash join original captures, preserve existing16MiB
 # stream and512KiB cleanup receipt caps. Never reinterpret protocol as PASS.
 C.need(record['argv'][0]=='/usr/bin/qemu-system-aarch64'and re.fullmatch('[a-f0-9]{32}',nonce),'one actual owned QEMU/nonce')
 def stream(raw,side):
  C.need(type(raw)is bytes and len(raw)<=16*1024**2 and len(raw)==record[side+'_bytes']and C.sha(raw)==record[side+'_sha256'],'original QEMU stream join')
  cap=65536 if side=='stdout'else 4096;preview=raw[-cap:]
  return dict(bytes=len(raw),sha256=C.sha(raw),preview_bytes=len(preview),preview_base64=base64.b64encode(preview).decode(),omitted_bytes=len(raw)-len(preview),truncated=len(preview)<len(raw))
 out=stream(stdout,'stdout');err=stream(stderr,'stderr');lines=stdout.splitlines();prefix=('APPS6_UPDATE16K '+nonce+' ').encode()
 counts=dict(protocol_prefix=sum(x.startswith(b'APPS6_UPDATE16K ')for x in lines),nonce_bound_prefix=sum(x.startswith(prefix)for x in lines),guest_error_prefix=sum(x.startswith(b'APPS6_UPDATE16K_ERROR ')for x in lines))
 value=dict(status='FAILED_QEMU_PROTOCOL_OR_READBACK_DATA_NOT_ACCEPTANCE',nonce=nonce,stdout=out,stderr=err,prefix_counts=counts)
 C.need(len(C.encoded(value))<=128*1024,'bounded failure QEMU metadata within existing512KiB cleanup receipt');return value

def run(a,argv,image,public,raw,old,seconds):
 C.need(seconds==3900,'unchanged original transaction budget');profile,kimage,_=authorize(a);bindings,env=mounts(argv)
 work=public.parent/'update16k';C.need(not work.exists() and re.fullmatch('sha256:[0-9a-f]{64}',image),'fresh work and exact owned producer image');work.mkdir(mode=0o700);disks=work/'disks';disks.mkdir();nonce=os.urandom(16).hex()
 selection=dict(nonce=nonce,case=a.case,kernel=profile,bindings={n:dict(readonly=v['readonly']) for n,v in bindings.items()},env=env,image=image,uid=os.getuid(),gid=os.getgid(),source_files=C.check_source(a.implementation),runner_files={p.name:C.row(p) for p in C.HERE.glob('*.py')})
 
 for p in C.HERE.glob('*.py'):shutil.copyfile(p,work/p.name)
 C.save(work/'selection.json',selection);shutil.copyfile(kimage,work/'Image');C.need(C.row(work/'Image')==profile['Image'],'copied actual16K Image')
 C.need(Path(bindings['/upgrade-signing']['source'])==raw/'test-signing','existing owned TEST signer only')
 old.command(['/usr/bin/gpgconf','--homedir',str(raw/'test-signing'),'--kill','all'],public/'updater16k-signing-retirement.log',15)
 input_before=snapshot(bindings);C.save(work/'input-map.json',input_before)
 runtime=C.load('supervisor',a.implementation/'scripts/ci/glibc-owned-runtime/runner.py');records=[];actors=[];retired=False;error=None;prepare_error=None;qemu_capture=None;qemu_error=None
 def command(cmd,timeout=30,cap=2*1024**2,allow=False):
  nonlocal prepare_error,qemu_capture
  record,out,err,exc=runtime.run_command(cmd,work,dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(work),TMPDIR=str(work)),timeout,cap)
  records.append(record);C.save(public/'updater16k-commands.json',records)
  if cmd[0]=='/usr/bin/qemu-system-aarch64':
   qemu_capture=(record,out,err)
   (public/'updater16k-uart.log').write_bytes(out);(public/'updater16k-qemu.stderr').write_bytes(err)
  if cmd[-len(('/workspace/disk.py','prepare')):]==['/workspace/disk.py','prepare'] and record['exit_code']:
   prepare_error=prepare_failure(record,err)
  C.need(exc is None and record['group_absence_verified'] is True and (allow or record['exit_code']==0),'VM command/group failure')
  return record,out,err
 def inspect(name):
  r,out,err=command(['/usr/bin/docker','inspect',name],allow=True)
  if r['exit_code']:
   C.need(r['exit_code']==1 and name in (out+err).decode(errors='replace') and b'No such' in out+err,'actor absence ambiguous');return None
  v=C.decode(out);C.need(len(v)==1 and v[0]['Image']==image and v[0]['Config']['Labels'].get('org.cachy-asahi.apps6-updater16k')==nonce,'exact owned actor');return v[0]['Id']
 def actor(role):
  name='caa-apps6-update16k-'+nonce+'-'+role;C.need(inspect(name) is None,'fresh actor');actors.append(name)
  cmd=['/usr/bin/docker','run','--name',name,'--label','org.cachy-asahi.apps6-updater16k='+nonce,'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m']
  for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP'):cmd+=['--cap-add='+cap]
  for path,dest in ((work,'/workspace'),(a.implementation,'/source')):
   cmd+=['--mount','type=bind,src='+str(path)+',dst='+dest+',readonly']
  for dest,b in bindings.items():
   cmd+=['--mount','type=bind,src='+b['source']+',dst='+dest+',readonly']
  cmd+=['--mount','type=bind,src='+str(disks)+',dst=/measurement','--env=CAA_APPS6_UPDATE16K_PREPARE=1','--entrypoint=/usr/bin/python3',image,'-I','-B','/workspace/disk.py',role]
  command(cmd,1900);C.need(inspect(name) is not None,'retained actor identity')
 try:
  actor('prepare');prep=C.decode(C.read(disks/'prepared.json'));selection['capabilities_sha256']=prep['capabilities_sha256'];C.save(work/'selection.json',selection)
  for n in ('boot','data'):C.need(C.row(disks/(n+'.raw'))==prep[n],'prepared sealed disk bytes')
  epoch=int(time.time());selection['launcher_epoch_s']=epoch
  r,uart,stderr=command(qemu(work/'Image',disks/'boot.raw',disks/'data.raw',epoch),seconds,16*1024**2);(public/'updater16k-uart.log').write_bytes(uart);(public/'updater16k-qemu.stderr').write_bytes(stderr)
  C.need(snapshot(bindings)==input_before,'original inputs/signer bytes and metadata changed')
  result=protocol(uart,selection,old_verify(a));C.save(work/'guest-files.json',result['files']);actor('export')
  for n,pin in result['files'].items():C.need(C.row(disks/'export'/n)==pin,'exact original debugfs readback');shutil.copyfile(disks/'export'/n,public/n)
  C.save(public/'updater16k-result.json',dict(status=C.PASS,scope='GENERIC16K_VM_NOT_NATIVE_HOST_OR_HARDWARE',guest=result,launcher_realtime=boot_witness(uart,selection),kernel=profile,source=C.row(a.implementation/C.OLD/'source-manifest.json'),input_map_sha256=C.sha(C.encoded(input_before)),original_uart=C.row(public/'updater16k-uart.log'),natural_qemu=r,kernel_receipt=C.row(a.kernel_receipt),preservation='PASS_EXACT_COMPLETE_ORIGINAL_INPUT_MAP',hardware='NOT_RUN',release='NOT_ADMITTED'))
 except BaseException as e:
  error=e
  if qemu_capture is not None:
   try:qemu_error=qemu_failure(*qemu_capture,nonce)
   except Exception as failure:qemu_error=dict(status='DIAGNOSTIC_UNAVAILABLE',error_type=type(failure).__name__)
 finally:
  try:
   C.need(all(r['group_absence_verified'] is True for r in records),'backing data retained unknown process group')
   for name in reversed(actors):
    identity=inspect(name)
    if identity is not None:command(['/usr/bin/docker','rm','--force',identity])
    C.need(inspect(name) is None,'owned actor remains')
   # Files may remain root-owned after preparation failure; scrub uses the same
   # owned image/label and only its recorded stage inode, never arbitrary roots.
   if (disks/'stage').exists():actor('scrub');name=actors[-1];command(['/usr/bin/docker','rm','--force',inspect(name)]);C.need(inspect(name) is None,'scrub remains')
   shutil.rmtree(work);retired=True
  except BaseException as e:
   if error is None:error=e
  C.save(public/'updater16k-cleanup.json',dict(status='PASS' if retired else 'RETAINED_ABSENCE_UNKNOWN',actors=actors,group_records=records,scope='OWNED_VM_DISKS_AND_CONSUMERS',error=None if error is None else dict(type=type(error).__name__,message=str(error)[:2048]),**({'prepare_failure':prepare_error} if prepare_error is not None else {}),**({'qemu_failure':qemu_error} if qemu_error is not None else {})))
 if error is not None:raise error
 C.need(retired,'VM cleanup incomplete')

def old_verify(a):
 old=C.load('verification_contract',a.implementation/C.OLD/'contract.py')
 adapter=old.scoped('verification_adapter',a.implementation/C.OLD/'adapter.py',{'contract':old});gate=old.scoped('verification_gate',a.implementation/C.OLD/'gate.py',{'contract':old});cache=old.scoped('verification_cache',a.implementation/C.OLD/'before_cache.py',{'contract':old})
 return old.scoped('verification_owner',a.implementation/C.OLD/'run.py',{'contract':old,'adapter':adapter,'gate':gate,'before_cache':cache}).verify_result


def retire_outer(old,path,result,public):
 proof=public/'updater16k-cleanup.json'
 work=public.parent/'update16k'
 if work.exists() or (proof.exists() and C.decode(C.read(proof))['status']!='PASS'):
  result['upgrade_volume_cleanup']='RETAINED_VM_ABSENCE_UNKNOWN';return ['VM backing data retained: owned consumer/group absence unknown']
 return old.retire_outer(path,result)
