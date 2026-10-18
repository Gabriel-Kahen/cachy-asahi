"""Trusted PID1 owns startup, one supervised worker and exact lease retirement."""
import ctypes,os,sys,time,types,copy
from pathlib import Path
import inputs,prerequisites,runtime_policy as contract,leases,bootstrap_loader,service,supervisor,dispose
P,C,_,B=inputs.broker()

def run(value):
 contract.gate(value);C.pid1();started=time.monotonic();deadline=started+10500
 guest=inputs.original('_immutable_held_nofile','scripts/ci/glibc-gnu-provider-installed16k/guest.py');selected=guest.C.decode(guest.C.read('/installed16k/selection.json'));P.need(selected['source_sha']==value['actual_source']and selected['nonce']==value['broker']['nonce']==value['bootstrap']['nonce'],'actual original selection source/fresh nonce');nofile=guest.observer_file_limit()
 marker=Path('/proc/cmdline').read_text();P.need(len(marker)<=65536 and marker.split().count('caa_gnu_immutable_runtime=1')==1,'one explicit new-purpose boot marker')
 native=contract.private(value,'native_map',256*1024**2)
 # Exact four private Root docs are byte-joined by Context; outer gate must
 # provide genuine decision parsers. None is fabricated by this entry point.
 docs={name:contract.private(value,name,4*1024**2)for name in('kernel_build_decision','kernel_boot_decision','source_decision','producer_retirement')}
 prerequisites.boot(docs['kernel_boot_decision'],value['kernel_build_decision'])
 image=contract.private(value,'source_image_receipt',4*1024**2);P.need(image['original_snapshot']==value['native_map'],'same producer native snapshot/image custody')
 proc=inputs.original('_gnu_pid1_original_proc','scripts/ci/glibc-gnu-provider-lifecycle/proc_mount.py');mounts=leases.Leases(proc,C.pid1);bootstrap=bootstrap_loader.load(mounts,native)
 # Bind backing major/minors only from actual readonly exact-size guest blocks.
 value=copy.deepcopy(value);w=value['broker']['verity'];a=bootstrap.dm.block('/dev/vdc',8*1024**3,True);b=bootstrap.dm.block('/dev/vdd',value['bootstrap']['tree']['bytes'],True);P.need(a!=b,'distinct real readonly data/hash devices');w['data_device']=str(os.major(a))+':'+str(os.minor(a));w['hash_device']=str(os.major(b))+':'+str(os.minor(b));C.selection(value['broker'])
 api,modules=C.source_api();F=modules['full_root'];limits=F.Limits(deadline=min(deadline,time.monotonic()+600),max_packages=574,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 device=prepared=context=None;transport=None;row=None
 try:
  device,prepared,context=bootstrap.prepare_pid1(value['bootstrap'],value['broker'],limits)
  # Disposal FD is retained by PID1 only, before control-node retirement.
  a,b=B.pair();transport=service.Service(a,b,context,mounts);command,proof=supervisor.load(transport);seconds=int(deadline-time.monotonic());P.need(0<seconds<=10500,'cold observation consumes original shared worker ceiling')
  row,out,err,error=command(['/usr/bin/python3','-I','-B','/immutable/entry.py','worker',str(b.fileno()),value['broker']['nonce']],Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),seconds,512*1024,service=transport)
  P.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True and not err,'original worker exit/retirement/closed stderr');records=out.splitlines();P.need(len(records)==1,'one closed new-purpose worker record');result=P.decode(records[0]);P.need(result['purpose']=='GNU_IMMUTABLE_RUNTIME_V1'and result['nonce']==value['broker']['nonce']and result['status']=='SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT'and result['worker_mask']==P.WORKER_MASK,'new-purpose worker full lifecycle result')
  retired=transport.retired(row);P.need(retired['leases']==9,'one original preflight plus eight real runtime leases')
  joined=context.map_join;cleanup=dispose.retire(bootstrap,device,prepared,context,row,mounts)
  return dict(purpose='GNU_IMMUTABLE_RUNTIME_V1',status='FULL_LIFECYCLE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED',observer_nofile=nofile,nonce=value['broker']['nonce'],page_size=os.sysconf('SC_PAGE_SIZE'),kernel=os.uname().release,worker=result,supervisor=row,leases=retired,source_map_join=joined,cleanup=cleanup,source_authorities='EXACT_PRIVATE_BYTES_NOT_EXPORTED',hardware='NOT_RUN',release='NOT_ADMITTED')
 finally:
  # Unknown child/mount state NEVER removes backing devices or invents cleanup.
  if row is not None and row['group_absence_verified']is True:
   if transport is not None and mounts.active is not None:transport.retired(row)
  if prepared is not None and row is not None and row['group_absence_verified']is True and mounts.active is None:prepared.close()

if __name__=='__main__':
 value=P.decode(contract.read(Path('/immutable/policy.json'),1024**2));print(P.encode(run(value)).decode(),end='')
