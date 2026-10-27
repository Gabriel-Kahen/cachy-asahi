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
    original_clock = _ORIGINAL_CLOCK.guest_handoff(value, selected)
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
            row, out, err, error = command(['/usr/bin/python3', '-I', '-B', '/immutable/entry.py', 'worker', str(b.fileno()), value['broker']['nonce']], Path('/tmp'), dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME='/tmp', TMPDIR='/tmp', PYTHONDONTWRITEBYTECODE='1', CAA_ORIGINAL_TRUST_CLOCK=_ORIGINAL_CLOCK.pack_receipt(original_clock)), seconds, 512 * 1024, service=transport)
        except BaseException:
            try:
                api['_phase'](b'LIFECYCLE_FAIL')
            except BaseException:
                pass
            raise
        api['_phase'](b'LIFECYCLE_END')
        if error is not None or row['exit_code'] != 0 or row['group_absence_verified'] is not True or err:
            worker_return_data(value['broker']['nonce'],row,out,err,error,transport)
        api['_phase'](b'READBACK_BEGIN')
        try:
            if error is not None or row['exit_code'] != 0 or err:
                relay_worker_failure(err,value['broker']['nonce'])
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

def worker_return_data(nonce,row,out,err,error,service):
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
  service_position=service.failure_position()
  phases=('NO_VALIDATED_REQUEST','SOURCE_CONTEXT_CHECK','SOURCE_CAPACITY','SOURCE_SEND','SOURCE_COMPLETE')+tuple('LEASE_'+op+'_'+case+'_'+step for op in('OPEN','CLOSE')for case in('PROBE','PRISTINE','MODIFIED')for step in('CONTEXT_BEFORE','ACTION','CONTEXT_AFTER','SEND','COMPLETE'))
  if type(service_position)is not dict or set(service_position)!={'phase','request_seq'}or service_position['phase']not in phases or type(service_position['request_seq'])is not int or not 0<=service_position['request_seq']<=64 or(service_position['phase']=='NO_VALIDATED_REQUEST')is not(service_position['request_seq']==0):return
  allowed=(tuple('SNAPSHOT_'+case.upper()+'_'+phase.upper().replace('-','_')for case in('pristine','modified')for phase in('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after'))+('COPY_SELECTED_OBSERVE','COPY_COPIED_TREE','COPY_CAPABILITY_RESTORE','COPY_COPY_DATA'))+('OP_SOURCE_OBSERVATION', 'OP_TARGET_OBSERVATION', 'OP_TARGET_CAPABILITIES', 'OP_TARGET_AUXILIARY', 'OP_COPY_DATA', 'OP_SOURCE_ROOT_CHECK', 'OP_SOURCE_PARENT', 'OP_LIFETIME_ENTER', 'OP_LIFETIME_BODY', 'OP_LIFETIME_EXIT', 'OP_CONTEXT_LIMITS', 'OP_CONTEXT_ADAPTER')
  labels=[]
  for label in allowed:
   marker=b'GNU_WORKER_FAILURE_DATA '+label.encode('ascii')+b'\n';position=0 if err.startswith(marker)else err.find(b'\n'+marker)
   if position>=0:labels.append((position,label))
  value=dict(schema=2,status='GNU_WORKER_RETURN_SERVICE_FAILURE_DATA_ONLY',nonce=nonce,service=service_position,exit_code=row['exit_code'],group_absence_verified=row['group_absence_verified'],seconds=seconds,time_limit=row['time_limit'],output_limit=row['output_limit'],streams=streams,error_present=error is not None,error=error_pin,worker_failure_labels=[label for _,label in sorted(labels)[:8]],acceptance=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
  if len(raw)>4096:return
  os.write(2,b'GNU_WORKER_RETURN_DATA '+raw+b'\n')
  worker_error_data(nonce,error,error_pin,service_position)
 except BaseException:pass

def relay_worker_failure(raw,nonce=None):
 # Bounded already-captured exception DATA only; empty-stderr success stays mandatory.
 try:
  if type(raw)is not bytes or len(raw)>512*1024:return
  allowed=((b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_SOURCE_BEFORE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_CLONE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_BEFORE574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_PRECOMMIT_REFUSED', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_PROVIDER574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_REINSTALLED574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_HELD574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_PRISTINE_SOURCE_AFTER', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_SOURCE_BEFORE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_CLONE', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_BEFORE574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_PRECOMMIT_REFUSED', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_PROVIDER574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_REINSTALLED574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_HELD574', b'GNU_WORKER_FAILURE_DATA SNAPSHOT_MODIFIED_SOURCE_AFTER', b'GNU_WORKER_FAILURE_DATA COPY_SELECTED_OBSERVE', b'GNU_WORKER_FAILURE_DATA COPY_COPIED_TREE', b'GNU_WORKER_FAILURE_DATA COPY_CAPABILITY_RESTORE', b'GNU_WORKER_FAILURE_DATA COPY_COPY_DATA'))+(b'GNU_WORKER_FAILURE_DATA OP_SOURCE_OBSERVATION', b'GNU_WORKER_FAILURE_DATA OP_TARGET_OBSERVATION', b'GNU_WORKER_FAILURE_DATA OP_TARGET_CAPABILITIES', b'GNU_WORKER_FAILURE_DATA OP_TARGET_AUXILIARY', b'GNU_WORKER_FAILURE_DATA OP_COPY_DATA', b'GNU_WORKER_FAILURE_DATA OP_SOURCE_ROOT_CHECK', b'GNU_WORKER_FAILURE_DATA OP_SOURCE_PARENT', b'GNU_WORKER_FAILURE_DATA OP_LIFETIME_ENTER', b'GNU_WORKER_FAILURE_DATA OP_LIFETIME_BODY', b'GNU_WORKER_FAILURE_DATA OP_LIFETIME_EXIT', b'GNU_WORKER_FAILURE_DATA OP_CONTEXT_LIMITS', b'GNU_WORKER_FAILURE_DATA OP_CONTEXT_ADAPTER');count=0;details=0
  for line in raw.splitlines(keepends=True)[:64]:
   if line.startswith(b'GNU_COPY_FAILURE_DETAIL ')and len(line)<=800 and nonce is not None:
    try:
     import json
     value=json.loads(line[len(b'GNU_COPY_FAILURE_DETAIL '):]);copy_detail_validate(value,nonce)
     canonical=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')+b'\n'
     if line[len(b'GNU_COPY_FAILURE_DETAIL '):]==canonical and value['ordinal']==details+1 and details<8:
      details+=1;os.write(2,line)
    except BaseException:pass
    continue
   if count<8 and line.endswith(bytes([10]))and line[:-1]in allowed:
    count+=1
    try:os.write(2,line)
    except BaseException:pass
 except BaseException:pass

"""Fixed public exception categories only; no paths, argv or error text."""
_COPY_DETAIL_STAGES=('SOURCE_PARENT_ENTER','COPY_BODY','SOURCE_PARENT_EXIT','COPY_DATA','LIFETIME_ENTER','LIFETIME_BODY','LIFETIME_EXIT')
_COPY_DETAIL_CAUSES=('ROOT_OBSERVATION_DEADLINE','CAPACITY_REFUSAL','FILE_CONTENT_REFUSAL','IDENTITY_OR_MOUNT_REFUSAL','OS_NO_SPACE','OS_IO','OS_FILESYSTEM_REFUSAL','OS_OTHER','OTHER_VALUE','INTERRUPTED','OTHER')
_COPY_DETAIL_EXCEPTIONS=('ValueError','OSError','MemoryError','KeyboardInterrupt','SystemExit','RuntimeError','Other')
def copy_detail_validate(v,nonce):
 import re
 if type(v)is not dict or set(v)!={'schema','nonce','ordinal','stage','cause','exception','errno','elapsed_ns','shared_remaining_ns','acceptance'}:raise ValueError('fixed copy failure DATA keys')
 if v['schema']!=1 or type(v['schema'])is not int or v['nonce']!=nonce or type(nonce)is not str or re.fullmatch('[a-f0-9]{32}',nonce)is None or v['acceptance']is not False:raise ValueError('fixed copy failure DATA identity')
 if type(v['ordinal'])is not int or not 1<=v['ordinal']<=8 or v['stage']not in _COPY_DETAIL_STAGES or v['cause']not in _COPY_DETAIL_CAUSES or v['exception']not in _COPY_DETAIL_EXCEPTIONS:raise ValueError('fixed copy failure DATA enums')
 if type(v['elapsed_ns'])is not int or not 0<=v['elapsed_ns']<=10800*10**9:raise ValueError('bounded actual copy elapsed')
 if v['shared_remaining_ns']is not None and(type(v['shared_remaining_ns'])is not int or not -10800*10**9<=v['shared_remaining_ns']<=10800*10**9):raise ValueError('bounded actual shared remaining')
 if v['errno']is not None and(type(v['errno'])is not int or not 1<=v['errno']<=4095):raise ValueError('bounded public errno')
 return v

if __name__=='__main__':
 value=P.decode(contract.read(Path('/immutable/policy.json'),1024**2));print(P.encode(run(value)).decode(),end='')


def worker_error_data(nonce,error,error_pin,position):
 """Fixed public service failure DATA; no arbitrary exception text or contents."""
 try:
  import hashlib,json,re
  if error is None or type(nonce)is not str or re.fullmatch('[a-f0-9]{32}',nonce)is None:return
  if type(error_pin)is not dict or set(error_pin)!={'bytes','sha256'}:return
  if type(error_pin['bytes'])is not int or not 0<=error_pin['bytes']<=4096 or type(error_pin['sha256'])is not str or re.fullmatch('[a-f0-9]{64}',error_pin['sha256'])is None:return
  phases=('NO_VALIDATED_REQUEST','SOURCE_CONTEXT_CHECK','SOURCE_CAPACITY','SOURCE_SEND','SOURCE_COMPLETE')+tuple('LEASE_'+op+'_'+case+'_'+step for op in('OPEN','CLOSE')for case in('PROBE','PRISTINE','MODIFIED')for step in('CONTEXT_BEFORE','ACTION','CONTEXT_AFTER','SEND','COMPLETE'))
  if type(position)is not dict or set(position)!={'phase','request_seq'}or position['phase']not in phases or type(position['request_seq'])is not int or not 0<=position['request_seq']<=64 or(position['phase']=='NO_VALIDATED_REQUEST')is not(position['request_seq']==0):return
  classes=(ValueError,RuntimeError,OSError,FileNotFoundError,PermissionError,TimeoutError,InterruptedError,MemoryError,KeyboardInterrupt,SystemExit)
  kind=type(error).__name__ if type(error)in classes else'Other'
  public_guard=None
  if type(error)is ValueError and type(error.args)is tuple and len(error.args)==1 and type(error.args[0])is str and error.args[0]in _SERVICE_PUBLIC_GUARDS:
   raw=error.args[0].encode('utf-8')
   if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=error_pin:return
   public_guard=error.args[0]
  number=error.errno if type(error)in(OSError,FileNotFoundError,PermissionError,TimeoutError,InterruptedError)else None
  if type(number)is not int or not 1<=number<=4095:number=None
  value=dict(schema=1,status='GNU_SERVICE_ERROR_FIXED_PUBLIC_DATA_ONLY',nonce=nonce,service=dict(position),exception=kind,errno=number,public_guard=public_guard,error=dict(error_pin),acceptance=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('ascii')
  if len(raw)>4096:return
  os.write(2,b'GNU_SERVICE_ERROR_DATA '+raw+b'\n')
 except BaseException:pass

_SERVICE_PUBLIC_GUARDS=('absent dev/null placeholder', 'actual dev/null bind source root/device/fs/flags mount row', 'actual harmless root-owned dev/null', 'actual proc device and superblock readonly', 'actual required proc mount flags/type/source/root', 'actual target is exact source dev/null inode/device/rdev/mode/owner', 'all baseline mount rows and their order held', 'all leases strictly retired', 'all worker/descendant groups absent before mount cleanup', 'at most one two-mount lease', 'at most ten original interruption runtime mount lifetimes', 'bounded complete mount inventory', 'bounded mount count', 'bounded runtime mount receipt', 'caller security/namespace/readonly mount metadata drift', 'canonical mount row', 'complete original mount inventory restored', 'dev/null source mount available', 'duplicate mount ID', 'exact active lease required', 'exact lease target paths', 'exact legacy unmount/absence required', 'exact mount syscall result', 'exact newly mounted row count', 'exact original mount call failed', 'exact readonly proc mount row required', 'exact root-owned source dev/null character device', 'exact source request', 'finite direct mount operation receipts', 'finite mount row count', 'finite mount row shape', 'finite namespace id map', 'finite security profile text', 'finite self status field', 'fresh empty owned proc target', 'fresh empty proc and unmounted dev/null targets', 'fresh single-link empty placeholder', 'fresh unmounted proc target', 'named probe parent changed', 'namespace identity encoding', 'no preexisting dev/null placeholder', 'no unretired mount rows', 'one exact dev/null bind mount row', 'one exact known same-role GNU marker only', 'one exact mount API operation', 'one newly owned mount row', 'one newly owned proc mount', 'one ordered original proc/dev lease', 'only exact registered lease rows added; all baseline rows whole held', 'only exact registered mount may unmount', 'only exact registered owned mount may be retired', 'only fixed proc/dev lease operations', 'ordered authenticated bounded request', 'original bounded native10cap/NNP/seccomp readback', 'original umount0/absence', 'owned mount path has no symlink alias', 'owned mount path identity/mode', 'owned mount target or parent identity changed', 'owned mount target unexpectedly occupied', 'owned placeholder/probe identity', 'owned private probe parent', 'owned same-role GNU proc diagnostic only', 'probe cleanup path/parent/mount drift', 'proc diagnostic input bound', 'proc receipt bound', 'registered actual whole mount row', 'required exact legacy mount failed', 'required exact legacy readonly proc mount failed', 'reserved worker alive', 'runtime security/namespace/mount source drift', 'selected proc mount bytes bound', 'selected proc mount inventory bound', 'self mount inventory unavailable', 'self mount row shape', 'self security status unavailable', 'two exact owned GNU case runtime roots only', 'unambiguous dev/null covering mount')

# ORIGINAL_SIGNATURE__ORIGINAL_CLOCK
_ORIGINAL_CLOCK_BODY=b'# SPDX-License-Identifier: MIT\n"""Same-run host realtime handoff; only dedicated guest PID1 may set a clock."""\nimport base64,json,os,re,stat,time\nfrom pathlib import Path\nMARKER=\'caa_gnu_original_clock=\'\nMIN_EPOCH_NS=1779031879*10**9\nMAX_STARTUP_NS=1200*10**9\nFIELDS={\'schema\',\'source_sha\',\'ref\',\'run_id\',\'nonce\',\'native_epoch_ns\',\'native_monotonic_ns\'}\ndef need(ok,why):\n if not ok:raise ValueError(why)\ndef encode(v):return json.dumps(v,sort_keys=True,separators=(\',\',\':\'),allow_nan=False).encode(\'ascii\')\ndef pairs(rows):\n v={}\n for k,x in rows:need(k not in v,\'duplicate original-clock field\');v[k]=x\n return v\ndef decode(raw):return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,\'finite original clock\'))\ndef identity(v):\n need(type(v)is dict and set(v)==FIELDS and type(v[\'schema\'])is int and v[\'schema\']==1,\'complete native clock handoff\')\n need(type(v[\'source_sha\'])is str and re.fullmatch(\'[a-f0-9]{40}\',v[\'source_sha\'])and type(v[\'ref\'])is str and re.fullmatch(\'codex/[a-z0-9-]+\',v[\'ref\'])and type(v[\'run_id\'])is int and 0<v[\'run_id\']<2**63 and type(v[\'nonce\'])is str and re.fullmatch(\'[a-f0-9]{32}\',v[\'nonce\']),\'same-run clock selectors\')\n need(type(v[\'native_epoch_ns\'])is int and MIN_EPOCH_NS<=v[\'native_epoch_ns\']<2**63 and type(v[\'native_monotonic_ns\'])is int and 0<v[\'native_monotonic_ns\']<2**63,\'bounded fresh native clock sample\')\n return v\n\ndef host_argv(argv,volume):\n """Called immediately before the original supervised QEMU launch, never SOURCE."""\n need(type(argv)is list and argv and argv[0]==\'/usr/bin/qemu-system-aarch64\'and argv.count(\'-append\')==1 and all(type(x)is str for x in argv),\'one unchanged native QEMU cmdline\')\n path=Path(volume).parent.parent/\'selection.json\';need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),\'same native owner selection\')\n fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)\n try:\n  before=os.fstat(fd);stat_identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)\n  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.geteuid()and 0<before.st_size<=65536,\'ordinary bounded native selection\')\n  raw=bytearray()\n  while len(raw)<=before.st_size:\n   part=os.read(fd,min(65536,before.st_size-len(raw)+1))\n   if not part:break\n   raw.extend(part)\n  need(len(raw)==before.st_size and stat_identity(before)==stat_identity(os.fstat(fd))==stat_identity(path.lstat()),\'native selection stable FD/path through clock sample\')\n  selected=decode(bytes(raw))\n finally:os.close(fd)\n source=os.environ.get(\'SOURCE_SHA\');need(source==os.environ.get(\'WORKFLOW_SHA\')==selected[\'source_sha\'],\'native source/workflow clock identity\')\n run=os.environ.get(\'GITHUB_RUN_ID\',\'\');need(run.isdecimal(),\'native genuine run clock identity\')\n v=identity(dict(schema=1,source_sha=source,ref=os.environ.get(\'GITHUB_REF_NAME\'),run_id=int(run),nonce=selected[\'nonce\'],native_epoch_ns=time.time_ns(),native_monotonic_ns=time.monotonic_ns()))\n token=base64.urlsafe_b64encode(encode(v)).decode(\'ascii\');need(len(token)<=1024,\'bounded native clock kernel token\')\n out=list(argv);index=out.index(\'-append\')+1;need(index<len(out)and not any(s.startswith(MARKER)for s in out[index].split()),\'native clock operand cannot be preselected\');out[index]+=\' \'+MARKER+token\n need(len(out[index].encode())<=65536,\'bounded full native clock cmdline\')\n return out\n\ndef guest_handoff(value,selected,cmdline=None):\n """Validate Source-selected nonce/run before setting this guest\'s REALTIME only."""\n need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine==\'aarch64\'and os.sysconf(\'SC_PAGE_SIZE\')==16384,\'dedicated real16K aarch64 root PID1 only; never host or worker clock\')\n line=Path(\'/proc/cmdline\').read_text()if cmdline is None else cmdline\n need(type(line)is str and len(line.encode())<=65536 and line.split().count(\'caa_gnu_immutable_runtime=1\')==1,\'one actual immutable guest clock purpose\')\n tokens=[s[len(MARKER):]for s in line.split()if s.startswith(MARKER)];need(len(tokens)==1 and len(tokens[0])<=1024,\'one same-run native clock token\')\n try:raw=base64.b64decode(tokens[0],altchars=b\'-_\',validate=True)\n except ValueError:raise ValueError(\'canonical native clock base64\')from None\n need(base64.urlsafe_b64encode(raw).decode()==tokens[0],\'canonical native clock encoding\');v=identity(decode(raw));need(encode(v)==raw,\'canonical source-owned native clock record\')\n need(v[\'source_sha\']==value[\'actual_source\']==selected[\'source_sha\']and v[\'ref\']==value[\'actual_ref\']and str(v[\'run_id\'])==str(value[\'actual_run\'])and v[\'nonce\']==selected[\'nonce\']==value[\'broker\'][\'nonce\']==value[\'bootstrap\'][\'nonce\'],\'clock same actual source/ref/run/fresh original nonce\')\n monotonic=time.monotonic_ns();need(0<monotonic<=MAX_STARTUP_NS,\'guest clock handoff before original1200-second cold-start window\')\n before=time.time_ns();target=v[\'native_epoch_ns\']+monotonic\n need(before<=target+MAX_STARTUP_NS,\'guest future clock is refused, never rewound to hide expiry\')\n changed=before<target\n if changed:time.clock_settime_ns(time.CLOCK_REALTIME,target)\n after=time.time_ns();need(target<=after<=target+MAX_STARTUP_NS and after>=before,\'guest realtime readback and forward-only handoff\')\n return dict(schema=1,status=\'PASS_GUEST_REALTIME_HANDOFF\',source_sha=v[\'source_sha\'],ref=v[\'ref\'],run_id=v[\'run_id\'],nonce=v[\'nonce\'],native_epoch_ns=v[\'native_epoch_ns\'],native_monotonic_ns=v[\'native_monotonic_ns\'],guest_before_ns=before,guest_after_ns=after,guest_monotonic_ns=monotonic,clock_set=changed)\n\ndef pack_receipt(v):\n raw=encode(v);need(len(raw)<=2048,\'bounded PID1 clock receipt\');return base64.urlsafe_b64encode(raw).decode(\'ascii\')\ndef unpack_receipt(text):\n need(type(text)is str and 0<len(text)<=4096,\'explicit PID1 clock environment handoff\')\n raw=base64.b64decode(text,altchars=b\'-_\',validate=True);need(base64.urlsafe_b64encode(raw).decode()==text and len(raw)<=2048,\'canonical bounded PID1 clock receipt\');v=decode(raw);need(encode(v)==raw,\'canonical PID1 clock receipt\');return v\n'
_ORIGINAL_CLOCK_PIN={'bytes': 6095, 'sha256': '83ca8d7d132ea7e84fc9dd427628cefa74ddde51727f7564a1923cc6380bc75a'}
import types as _original_signature_types
_ORIGINAL_CLOCK=_original_signature_types.ModuleType('<SOURCE_OWNED__ORIGINAL_CLOCK>')
if {'bytes':len(_ORIGINAL_CLOCK_BODY),'sha256':__import__('hashlib').sha256(_ORIGINAL_CLOCK_BODY).hexdigest()}!=_ORIGINAL_CLOCK_PIN:raise ValueError('whole original signature helper')
exec(compile(_ORIGINAL_CLOCK_BODY,'<SOURCE_OWNED__ORIGINAL_CLOCK>','exec'),vars(_ORIGINAL_CLOCK))
