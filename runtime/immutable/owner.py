"""Trusted PID1 owns startup, one supervised worker and exact lease retirement."""
import ctypes,os,sys,time,types,copy
from pathlib import Path
import inputs,prerequisites,runtime_policy as contract,leases,bootstrap_loader,service,supervisor,dispose
P,C,_,B=inputs.broker()
COLD_VALIDATION_PROFILE={'name': 'GNU_GENERIC16K_COLD_VALIDATION_1200_V1', 'seconds': 1200, 'shared_owner_ceiling': 10500, 'qemu_ceiling': 10800, 'fit_600': 'NOT_ESTABLISHED'}

def run(value):
    contract.gate(value)
    C.pid1()
    started = time.monotonic()
    deadline = started + 10500
    guest = inputs.original('_immutable_held_nofile', 'scripts/ci/glibc-debian-maintained-installed16k/guest.py')
    selected = guest.C.decode(guest.C.read('/debian-maintained-installed16k/selection.json'))
    P.need(selected['source_sha'] == value['actual_source'] and selected['nonce'] == value['broker']['nonce'] == value['bootstrap']['nonce'], 'actual original selection source/fresh nonce')
    nofile = guest.observer_file_limit()
    marker = Path('/proc/cmdline').read_text()
    P.need(len(marker) <= 65536 and marker.split().count('caa_gnu_immutable_runtime=1') == 1, 'one explicit new-purpose boot marker')
    native = contract.private(value, 'native_map', 256 * 1024 ** 2)
    docs = {name: contract.private(value, name, 4 * 1024 ** 2) for name in ('kernel_build_decision', 'kernel_boot_decision', 'source_decision', 'producer_retirement')}
    prerequisites.boot(docs['kernel_boot_decision'], value['kernel_build_decision'])
    image = contract.private(value, 'source_image_receipt', 4 * 1024 ** 2)
    P.need(image['original_snapshot'] == value['native_map'], 'same producer native snapshot/image custody')
    proc = inputs.original('_gnu_pid1_original_proc', 'scripts/ci/glibc-gnu-provider-lifecycle/proc_mount.py')
    mounts = leases.Leases(proc, C.pid1)
    bootstrap = bootstrap_loader.load(mounts, native)
    value = copy.deepcopy(value)
    w = value['broker']['verity']
    a = bootstrap.dm.block('/dev/vdc', 8 * 1024 ** 3, True)
    b = bootstrap.dm.block('/dev/vdd', value['bootstrap']['tree']['bytes'], True)
    P.need(a != b, 'distinct real readonly data/hash devices')
    w['data_device'] = str(os.major(a)) + ':' + str(os.minor(a))
    w['hash_device'] = str(os.major(b)) + ':' + str(os.minor(b))
    C.selection(value['broker'])
    api, modules = C.source_api()
    F = modules['full_root']
    limits = F.Limits(deadline=min(deadline, time.monotonic() + COLD_VALIDATION_PROFILE['seconds']), max_packages=574, max_nodes=500000, max_bytes=8 * 1024 ** 3, max_file_bytes=1024 ** 3)
    device = prepared = context = None
    transport = None
    row = None
    try:
        device, prepared, context = bootstrap.prepare_pid1(value['bootstrap'], value['broker'], limits)
        a, b = B.pair()
        transport = service.Service(a, b, context, mounts)
        command, proof = supervisor.load(transport)
        seconds = int(deadline - time.monotonic())
        P.need(0 < seconds <= 10500, 'cold observation consumes original shared worker ceiling')
        api['_phase'](b'LIFECYCLE_BEGIN')
        try:
            row, out, err, error = command(['/usr/bin/python3', '-I', '-B', '/immutable/entry.py', 'worker', str(b.fileno()), value['broker']['nonce']], Path('/tmp'), dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME='/tmp', TMPDIR='/tmp', PYTHONDONTWRITEBYTECODE='1'), seconds, 512 * 1024, service=transport)
        except BaseException:
            try:
                api['_phase'](b'LIFECYCLE_FAIL')
            except BaseException:
                pass
            raise
        api['_phase'](b'LIFECYCLE_END')
        if error is not None or row['exit_code'] != 0 or row['group_absence_verified'] is not True or err:
            worker_return_data(value['broker']['nonce'],row,out,err,error)
        api['_phase'](b'READBACK_BEGIN')
        try:
            if error is not None or row['exit_code'] != 0 or err:
                relay_worker_failure(err)
            P.need(error is None and row['exit_code'] == 0 and (row['group_absence_verified'] is True) and (not err), 'original worker exit/retirement/closed stderr')
            records = out.splitlines()
            P.need(len(records) == 1, 'one closed new-purpose worker record')
            result = P.decode(records[0])
            P.need(result['purpose'] == 'GNU_IMMUTABLE_RUNTIME_V1' and result['nonce'] == value['broker']['nonce'] and (result['status'] == 'SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT') and (result['worker_mask'] == P.WORKER_MASK), 'new-purpose worker full lifecycle result')
        except BaseException:
            try:
                api['_phase'](b'READBACK_FAIL')
            except BaseException:
                pass
            raise
        api['_phase'](b'READBACK_END')
        api['_phase'](b'CLEANUP_BEGIN')
        try:
            retired = transport.retired(row)
            P.need(retired['leases'] == 9, 'one original preflight plus eight real runtime leases')
            joined = context.map_join
            cleanup = dispose.retire(bootstrap, device, prepared, context, row, mounts)
        except BaseException:
            try:
                api['_phase'](b'CLEANUP_FAIL')
            except BaseException:
                pass
            raise
        api['_phase'](b'CLEANUP_END')
        return dict(cold_validation=dict(COLD_VALIDATION_PROFILE), purpose='GNU_IMMUTABLE_RUNTIME_V1', status='FULL_LIFECYCLE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED', observer_nofile=nofile, nonce=value['broker']['nonce'], page_size=os.sysconf('SC_PAGE_SIZE'), kernel=os.uname().release, worker=result, supervisor=row, leases=retired, source_map_join=joined, cleanup=cleanup, source_authorities='EXACT_PRIVATE_BYTES_NOT_EXPORTED', hardware='NOT_RUN', release='NOT_ADMITTED')
    finally:
        if row is not None and row['group_absence_verified'] is True:
            if transport is not None and mounts.active is not None:
                transport.retired(row)
        if prepared is not None and row is not None and (row['group_absence_verified'] is True) and (mounts.active is None):
            prepared.close()

def worker_return_data(nonce,row,out,err,error):
 # No argv, private paths, stdout/stderr payload, exception text or graph export.
 try:
  import hashlib,json,math,re
  if type(nonce)is not str or re.fullmatch('[a-f0-9]{32}',nonce)is None:return
  if type(row)is not dict or type(out)is not bytes or type(err)is not bytes or len(out)+len(err)>512*1024:return
  if type(row.get('exit_code'))is not int or not -255<=row['exit_code']<=255 or type(row.get('group_absence_verified'))is not bool:return
  if error is None and row['exit_code']==0 and row['group_absence_verified']is True and not err:return
  if type(row.get('time_limit'))is not int or not 0<row['time_limit']<=10500 or row.get('output_limit')!=512*1024:return
  seconds=row.get('seconds')
  if type(seconds)not in(int,float)or not math.isfinite(seconds)or not 0<=seconds<=10800:return
  def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  streams={name:pin(raw)for name,raw in(('stdout',out),('stderr',err))}
  if any(row.get(name+'_bytes')!=v['bytes']or row.get(name+'_sha256')!=v['sha256']for name,v in streams.items()):return
  error_pin=None
  if error is not None:
   text=str(error).encode('utf-8')
   if len(text)>4096:return
   error_pin=pin(text)
  allowed=tuple('SNAPSHOT_'+case.upper()+'_'+phase.upper().replace('-','_')for case in('pristine','modified')for phase in('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'))+('COPY_SELECTED_OBSERVE','COPY_COPIED_TREE','COPY_CAPABILITY_RESTORE','COPY_COPY_DATA')
  labels=[]
  for label in allowed:
   marker=b'GNU_WORKER_FAILURE_DATA '+label.encode('ascii')+b'\n';position=0 if err.startswith(marker)else err.find(b'\n'+marker)
   if position>=0:labels.append((position,label))
  value=dict(schema=1,status='GNU_WORKER_RETURN_FAILURE_DATA_ONLY',nonce=nonce,exit_code=row['exit_code'],group_absence_verified=row['group_absence_verified'],seconds=seconds,time_limit=row['time_limit'],output_limit=row['output_limit'],streams=streams,error_present=error is not None,error=error_pin,worker_failure_labels=[label for _,label in sorted(labels)[:8]],acceptance=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
  if len(raw)>4096:return
  os.write(2,b'GNU_WORKER_RETURN_DATA '+raw+b'\n')
 except BaseException:pass

def relay_worker_failure(raw):
 # Bounded already-captured exception DATA only; empty-stderr success stays mandatory.
 try:
  if type(raw)is not bytes or len(raw)>512*1024:return
  allowed=(b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_SOURCE_BEFORE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_CLONE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_BEFORE574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_PRECOMMIT_REFUSED', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_PROVIDER574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_REINSTALLED574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_HELD574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_SOURCE_AFTER', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_SOURCE_BEFORE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_CLONE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_BEFORE574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_PRECOMMIT_REFUSED', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_PROVIDER574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_REINSTALLED574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_HELD574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_SOURCE_AFTER', b'GNU_WORKER_FAILURE_DATA COPY_SELECTED_OBSERVE', b'GNU_WORKER_FAILURE_DATA COPY_COPIED_TREE', b'GNU_WORKER_FAILURE_DATA COPY_CAPABILITY_RESTORE', b'GNU_WORKER_FAILURE_DATA COPY_COPY_DATA');count=0
  for line in raw.splitlines(keepends=True)[:64]:
   if count<8 and line.endswith(bytes([10]))and line[:-1]in allowed:
    count+=1
    try:os.write(2,line)
    except BaseException:pass
 except BaseException:pass

if __name__=='__main__':
 value=P.decode(contract.read(Path('/immutable/policy.json'),1024**2));print(P.encode(run(value)).decode(),end='')
