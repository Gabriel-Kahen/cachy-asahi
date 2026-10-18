# SPDX-License-Identifier: MIT
"""One original lifecycle role, sealed media and actual16K child under3000s total."""
import os,shutil,time
from pathlib import Path
import contract as C
import adapter

def remaining(deadline,cap):
 seconds=min(cap,deadline-time.monotonic());C.need(seconds>0,'original shared3000 lifecycle deadline exhausted');return seconds

def qemu(image,boot,data,clock_ns):
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append','console=ttyAMA0 root=/dev/vda rw rootwait init=/init-repair16k caa_apps574_repair16k=1 arm64.nomops caa_clock_ns='+str(clock_ns),'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot','-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data','-serial','stdio']

def protocol(raw,s,native):
 C.need(len(raw)<=16*1024**2,'original UART cap');prefix=('APPS574_REPAIR16K '+s['nonce']+' ').encode();lines=[v.rstrip(b'\r') for v in raw.splitlines() if v.startswith(b'APPS574_REPAIR16K ')];C.need(len(lines)==3 and all(v.startswith(prefix) for v in lines),'three original nonce-bound boot/result/exit records');boot,result,end=[C.decode(v[len(prefix):]) for v in lines]
 C.need(boot['event']=='boot' and boot['page_size']==16384 and boot['architecture']=='aarch64' and boot['kernel']==s['kernel']['release'] and boot['kernel_profile_sha256']==C.sha(C.encoded(s['kernel'])) and boot['clock']['nofile']['after']==[8192,8192] and boot['clock']['seed_realtime_ns']==s['clock_seed_ns'],'actual page/kernel/clock/descriptor proof')
 fresh=boot['lease'];old=s['host_lease'];C.need(fresh['status']=='FRESH_ACTUAL_GUEST_SOURCE_LEASE' and fresh['before']==old and fresh['before_sha256']==s['host_lease_sha256'] and fresh['after']==dict(old,source_identity=fresh['source_identity']) and fresh['after_sha256']==C.sha(C.encoded(fresh['after'])) and fresh['changed_fields']==['source_identity'],'one freshly observed guest source lease change only')
 v=result['worker'];C.need(result['event']=='result' and result['status']==C.PASS and result['case']==v['case']==s['case'] and result['page_size']==16384 and result['lease_sha256']==fresh['after_sha256'] and v['status']=='PRIVATE_COMPLETE_CASE' and v['isolation']['after']==dict(mask=C.MASK,nnp=1,inh=0,amb=0) and v['isolation']['uid']==v['isolation']['gid']==0 and v['isolation']['groups']==[] and v['isolation']['seccomp']==2 and v['child']['exit_code']==0 and v['child']['group_absence_verified'] is True,'actual five-cap NNP single-case child retirement')
 C.need(v['source_tree_sha256']==s['source_tree_sha256'] and v['source_capabilities_sha256']==s['source_capabilities_sha256'] and v['ELF']['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT' and v['ELF']['count']>0,'actual complete source/capability/ELF preservation');C.need(end==dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED'),'actual guest mount retirement');return boot,result,end

def selected_command(args,native,role,root,output,report,api,argv,required,seconds,command):
 if role!='lifecycle':return command(argv,required,seconds)
 C.need(seconds==4320 and args.case==report['case'],'exact native4320 slot; separate VM3000 shared bound');deadline=time.monotonic()+3000;native,decisions,(profile,image,config)=C.authorize(args);C.need(time.monotonic()<deadline,'authority verification within lifecycle bound')
 prefix=['/usr/bin/docker','run','--name'];C.need(argv[:3]==prefix and argv[-1]=='/source/'+C.NATIVE+'/lifecycle.py','exact original lifecycle execution seam');name=argv[3];caps={v for v in argv if v.startswith('--cap-add=')};C.need(caps=={'--cap-add='+n for n in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP')} and '--ulimit=nofile=8192:8192' in argv,'unchanged five original caps/nofile')
 work=output/'repair16k';media=output/'repair16k-media';C.need(not work.exists() and not media.exists(),'fresh private VM bridge');work.mkdir(mode=0o700);media.mkdir(mode=0o700);execution=work/'execution';manifest=C.decode(C.read(root/C.NATIVE/'source-manifest.json'));adaptation=adapter.execution(root,execution,manifest)
 for p in C.HERE.glob('*.py'):shutil.copyfile(p,work/p.name)
 raw=C.read(root/C.NATIVE/'lifecycle.py');derived=adapter.lifecycle(raw);(work/'execution-lifecycle.py').write_bytes(derived);adaptation['lifecycle_entry']=dict(original=dict(bytes=len(raw),sha256=C.sha(raw)),derived=dict(bytes=len(derived),sha256=C.sha(derived)),changed_functions=['inspected','main'],added_function='_vm_backend',case_body='UNCHANGED');shutil.copyfile(image,work/'Image');C.need(C.row(work/'Image')==profile['Image'],'sealed exact accepted kernel Image')
 snapshot=C.decode(C.read(output/'snapshot-public/snapshot.json'));host_lease=C.read(output/'inputs/full574-lease.json',65536)
 env=dict(OWNER_TOKEN=report['token'],OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid()),CACHY_APPS574_LIFECYCLE='1',CACHY_APPS574_REPAIR_CASE=args.case)
 input_map=C.tree(output/'inputs')
 s=dict(media_identity=[media.stat().st_dev,media.stat().st_ino],input_map=input_map,phase='prepare',nonce=os.urandom(16).hex(),case=args.case,kernel=profile,image=report['image'],uid=os.getuid(),gid=os.getgid(),deadline_monotonic=deadline,env=env,source_files=C.check_source(root),runner_files={p.name:C.row(p) for p in work.glob('*.py')},source_tree_sha256=snapshot['tree_sha256'],source_capabilities_sha256=snapshot['source_capabilities_sha256'],host_lease=C.decode(host_lease),host_lease_sha256=C.sha(host_lease),execution_manifest_sha256=C.row(execution/'execution-manifest.json')['sha256'])
 for case,ref in C.gate(root,args.case)[1]['native_decisions'].items():
  (output/'lifecycle-public'/('repair16k-native-'+case+'.json')).write_bytes(native.checked(args.native_decisions,ref))
 for label,path in (('kernel-receipt',args.kernel_receipt),('kernel-authority',args.kernel_authority)):(output/'lifecycle-public'/('repair16k-'+label+'.json')).write_bytes(C.read(path,65536))
 C.save(work/'selection.json',s);state=dict(status='LIFECYCLE_RESERVED_NO_VM_RETIREMENT',nonce=s['nonce'],case=args.case,deadline_monotonic=deadline,groups=[]);C.save(output/'repair16k-state.json',state);result=None;error=None
 try:
  modified=list(argv);modified[-1]='/workspace/disk.py';at=modified.index('--entrypoint=/usr/bin/python3');modified[at:at]=['--mount','type=bind,src='+str(work)+',dst=/workspace,readonly','--mount','type=bind,src='+str(execution)+',dst=/execution,readonly','--mount','type=bind,src='+str(media)+',dst=/media'];result=command(modified,True,remaining(deadline,3000));observed=api.inspect(name,command);cid=api.verify_actor(observed,name,report['image'],native.LABEL,report['token']);C.need(observed['State']['Running'] is False and observed['State']['ExitCode']==0,'natural original preparation role exit')
  prepared=C.decode(C.read(media/'prepared.json'));C.need(prepared['nonce']==s['nonce'] and prepared['case']==args.case,'sealed media identity')
  for key in ('boot','data'):C.need(C.row(media/(key+'.raw'))==prepared[key],'complete sealed media bytes')
  runtime=C.load('qemu_group',root/'scripts/ci/glibc-owned-runtime/runner.py');s['clock_seed_ns']=time.time_ns();C.need(s['clock_seed_ns']>0,'original fresh runner realtime');qargv=qemu(work/'Image',media/'boot.raw',media/'data.raw',s['clock_seed_ns']);state.update(status='VM_REQUESTED_RETIREMENT_NOT_PROVEN',qemu_argv=qargv);C.save(output/'repair16k-state.json',state)
  record,out,err,failure=runtime.run_command(qargv,work,dict(native.ENV,HOME=str(work),TMPDIR=str(work)),remaining(deadline,3000),16*1024**2);state['groups'].append(record);C.save(output/'repair16k-state.json',state);(output/'lifecycle-public/repair16k-uart.log').write_bytes(out);(output/'lifecycle-public/repair16k-qemu.stderr').write_bytes(err)
  C.need(failure is None and record['exit_code']==0 and record['group_absence_verified'] is True,'natural QEMU/direct group retirement');boot,guest,end=protocol(out,s,native);s.update(phase='readback',guest_files=guest['files']);C.save(work/'selection.json',s)
  current=api.inspect(name,command);api.verify_actor(current,name,report['image'],native.LABEL,report['token'],cid);C.need(current['State']['Running'] is False and current['State']['ExitCode']==0,'same exited owned role before readback restart');command(['/usr/bin/docker','start','--attach',cid],True,remaining(deadline,3000));current=api.inspect(name,command);api.verify_actor(current,name,report['image'],native.LABEL,report['token'],cid);C.need(current['State']['Running'] is False and current['State']['ExitCode']==0,'same readback role natural exit')
  for n,pin in guest['files'].items():C.need(C.row(output/'lifecycle-public'/n)==pin,'complete exact original guest readback')
  C.need(C.tree(output/'inputs')==input_map,'original host authenticated inputs unchanged');C.check_source(root)
  life=native.result(C.decode(C.read(output/'lifecycle-public/lifecycle.json')));C.need(life['case']==args.case and all(v['full574_binding']['lease_sha256']==boot['lease']['after_sha256'] for v in life['transactions']+list(life['repairs'].values())),'original case validators and actual guest lease binding')
  remaining(deadline,3000)
  C.save(output/'lifecycle-public/repair16k-result.json',dict(status=C.PASS,case=args.case,kernel=profile,boot=boot,guest=guest,exit=end,natural_qemu=record,preparation=prepared,execution=adaptation,native_decisions={k:C.sha(C.encoded(v)) for k,v in decisions.items()},shared_lifecycle_seconds=3000,elapsed_seconds=3000-(deadline-time.monotonic()),scope='GENERIC16K_VM_NOT_NATIVE_HOST_OR_HARDWARE',hardware='NOT_RUN',release='NOT_ADMITTED'))
 except BaseException as e:error=e
 finally:
  safe=(bool(state['groups']) and all(v['group_absence_verified'] is True for v in state['groups'])) or (state['status']=='LIFECYCLE_RESERVED_NO_VM_RETIREMENT' and all(v['group_absence_verified'] is True for v in report['commands']))
  if safe:
   # Exact same original role must be naturally exited before private media deletion.
   try:
    current=api.inspect(name,command);C.need(current is not None and not current['State']['Running'],'owned media role remains active');api.verify_actor(current,name,report['image'],native.LABEL,report['token']);C.need(not (media/'stage').exists() and [media.stat().st_dev,media.stat().st_ino]==s['media_identity'],'exact private media root and completed staging retirement')
    for p in media.iterdir():C.need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.name in ('boot.raw','data.raw','prepared.json','stage-owner.json'),'closed private media file set');p.unlink()
    media.rmdir();shutil.rmtree(work);state['status']='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED'
   except BaseException as e:
    state['status']='RETAINED_VM_OR_MEDIA_ABSENCE_UNKNOWN'
    if error is None:error=e
  else:state['status']='RETAINED_VM_OR_MEDIA_ABSENCE_UNKNOWN'
  state['error']=None if error is None else dict(type=type(error).__name__,message=str(error)[:1024]);C.save(output/'repair16k-state.json',state)
 if error is not None:raise error
 C.need(state['status']=='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED','VM backing state retired');remaining(deadline,3000);return result
