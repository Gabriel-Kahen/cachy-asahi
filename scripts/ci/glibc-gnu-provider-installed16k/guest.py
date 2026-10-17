#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only held bootstrap drives unchanged ALPM574 lifecycle in disk clones."""
import base64
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def emit(nonce,value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(raw)<=512*1024,'guest receipt bound')
    print('GNU_INSTALLED16K '+nonce+' '+raw,flush=True)

def inner_failure_report(row):
    """PID1 observes the original report only after its writer group is absent."""
    value=dict(status='UNAVAILABLE_UNRETIRED_CHILD',path='/out/result.json',read_cap=8*1024**2,
               acceptance='FORBIDDEN_DIAGNOSTIC_ONLY_NO_COMPLETION')
    if row.get('group_absence_verified') is not True:return value
    try:raw=C.read('/out/result.json',8*1024**2)
    except FileNotFoundError:
        value['status']='MISSING_ORIGINAL_INNER_REPORT';return value
    except Exception as error:
        value.update(status='UNREADABLE_OR_OVER_CAP_INNER_REPORT',read_error=dict(type=type(error).__name__,message=str(error)[:512]));return value
    preview=raw[:65536]
    value.update(status='INVALID_ORIGINAL_INNER_REPORT',raw=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
                 preview_base64=base64.b64encode(preview).decode('ascii'),preview_bytes=len(preview),truncated=len(preview)!=len(raw)))
    try:
        report=C.decode(raw);C.need(type(report) is dict,'original inner report must be an object')
    except Exception as error:
        value['parse_error']=dict(type=type(error).__name__,message=str(error)[:512]);return value
    fields={}
    for name in ('status','error_type','error'):
        if name not in report:
            fields[name]=dict(status='MISSING_FIELD');continue
        item=report[name]
        if type(item) is not str:
            fields[name]=dict(status='INVALID_FIELD_TYPE',type=type(item).__name__);continue
        try:data=item.encode('utf8')
        except UnicodeEncodeError:
            fields[name]=dict(status='INVALID_UTF8_FIELD');continue
        bounded=data[:4096]
        fields[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),preview_utf8=bounded.decode('utf8',errors='replace'),
                          preview_bytes=len(bounded),truncated=len(data)!=len(bounded))
    value.update(status='READ_ORIGINAL_INNER_REPORT_DIAGNOSTIC_ONLY',fields=fields);return value

def child_failure(row,stdout,stderr,error,phase):
    """UART-only diagnostic of original captured buffers; never a guest result."""
    C.need(type(stdout) is type(stderr) is bytes and len(stdout)+len(stderr)<=512*1024,'original child capture bound')
    def stream(raw):
        preview=raw[:65536]
        return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),preview_base64=base64.b64encode(preview).decode('ascii'),
                    preview_bytes=len(preview),truncated=len(preview)!=len(raw))
    C.need(type(row) is dict and len(json.dumps(row,sort_keys=True,allow_nan=False))<=32768,'bounded original supervisor record')
    message=str(error).encode('utf8') if error is not None else b''
    return dict(event='child-failure',status='FAIL',phase=phase,supervisor_record=row,
                stdout=stream(stdout),stderr=stream(stderr),
                error=None if error is None else dict(type=type(error).__name__,**stream(message)),
                capture='ORIGINAL_SUPERVISOR_CAPTURED_BUFFERS_MAY_BE_PARTIAL_ON_LIMIT_OR_INTERRUPTION',
                inner_report=inner_failure_report(row),
                acceptance='FORBIDDEN_DIAGNOSTIC_ONLY_NO_GUEST_FILES_OR_COMPLETION')

def worker():
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    C.need(re.fullmatch('[0-9a-f]{32}',nonce) and os.getpid()!=1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'fixed actual16K child required')
    C.need('caa_gnu_installed16k=1' in Path('/proc/cmdline').read_text().split(),'dedicated guest marker required')
    profile=C.read('/installed16k/container16k.py');C.need(C.sha(profile)==selection['adapter_sha256'],'exact generated lifecycle executable required')
    import sandbox
    isolation=sandbox.apply();C.save('/out/isolation.json',isolation)
    os.environ.update(CACHY_GNU_PROVIDER_LIFECYCLE='1',INPUT_INDEX_SHA256=selection['input_index_sha256'],OUTPUT_UID='0',OUTPUT_GID='0',PYTHONDONTWRITEBYTECODE='1')
    worker=C.load('guest_worker','/installed16k/container16k.py')
    code=worker.main();native=worker.C;index,_,_,_=native.configuration(Path('/inputs'),selection['input_index_sha256']);api=native.helpers(Path('/source'))
    report=C.decode(C.read('/out/result.json',8*1024**2))
    C.need(code==0 and report['status']=='PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE','actual full installed lifecycle failed')
    stages=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after')
    caps=api['capabilities'].records(index,report['cases'],stages)
    C.need(not any(Path('/work').iterdir()),'guest clones remain')
    for case in native.CASES:
        row=report['cases'][case]
        C.need(row['status']=='PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE' and row['source_before']==row['source_after']==index['source_nodes_sha256'] and row['copy_lifetime']['cleanup']=='PASS-owned-workspace-removed','full574 complete source/copy/cleanup checks required')
        for phase in ('before_runtime','provider_runtime','reinstalled_runtime','held_runtime'):
            C.need(row[phase]['result']['page_size']==16384 and row[phase]['normal_parent_and_child'] is True,'all eight normal-interpreter runtime observations actual16K')
    files={};total=0
    for path in sorted(Path('/out').iterdir()):
        C.need(re.fullmatch(r'(result\.json|isolation\.json|command-[0-9]{3}\.(stdout|stderr)|(pristine|modified)-[a-z0-9-]+(-root\.json\.gz|\.log))',path.name),'closed native evidence filename')
        C.read(path,64*1024**2);files[path.name]=C.row(path);total+=path.stat().st_size
    C.need(len(files)<=256 and total<=512*1024**2,'complete guest evidence bound')
    value=dict(event='result',status=C.PASS,page_size=16384,source_nodes_sha256=index['source_nodes_sha256'],capabilities=caps,isolation=isolation,files=files,bytes=total,source_readback='COMPLETE574_PAYLOAD_DB_METADATA_CAPABILITY_HARDLINK_CHECKS',normal_runtime_observations=8,interrupted_lane='NOT_IMPLEMENTED_SEPARATE_FUTURE_CASE',hardware='NOT_RUN',release='NOT_ADMITTED')
    emit(nonce,value)

def observer_file_limit():
    """Match native trial's finite descriptor budget before authority reduction."""
    before=resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192))
    after=resource.getrlimit(resource.RLIMIT_NOFILE)
    C.need(after==(8192,8192),'exact inherited native observer descriptor limit')
    return dict(before=list(before),after=list(after),scope='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD')

def run():
    C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0,'root guest bootstrap only')
    selection=C.decode(C.read('/installed16k/selection.json'));nonce=selection['nonce']
    nofile=observer_file_limit()
    # The worker cannot inspect a more privileged bootstrap's memory or FDs.
    libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(4,0,0,0,0)==0,'protect root bootstrap')
    C.need(os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'actual16K boot identity')
    emit(nonce,dict(event='boot',page_size=16384,kernel=os.uname().release,architecture='aarch64',kernel_profile_sha256=selection['kernel_profile_sha256'],observer_nofile=nofile))
    runtime=C.load('guest_supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py')
    row,stdout,stderr,error=runtime.run_command(['/usr/bin/python3','-I','-B','/installed16k/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),10500,512*1024)
    if not (error is None and row['exit_code']==0 and row['group_absence_verified']):
        emit(nonce,child_failure(row,stdout,stderr,error,'exit-or-retirement'))
    C.need(error is None and row['exit_code']==0 and row['group_absence_verified'],'lifecycle child exit/group retirement failed')
    lines=stdout.splitlines();closed=len(lines)==1 and lines[0].startswith(('GNU_INSTALLED16K '+nonce+' ').encode()) and not stderr
    if not closed:emit(nonce,child_failure(row,stdout,stderr,error,'closed-worker-result'))
    C.need(closed,'one closed worker result only')
    print(lines[0].decode(),flush=True)
    # Only PID1 retains authority to retire mount topology and power off.
    import subprocess
    for point in ('/out','/work','/held','/source','/inputs'):
        result=subprocess.run(['/usr/bin/umount',point],stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
        C.need(result.returncode==0 and not os.path.ismount(point),'guest mount retirement failed')
    emit(nonce,dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_CLONES_REMOVED'))

if __name__=='__main__':
    if sys.argv[1:]==['worker']:
        worker();raise SystemExit(0)
    try:run()
    except BaseException as error:print('GNU_INSTALLED16K_ERROR '+type(error).__name__+' '+str(error)[:512],flush=True)
    finally:
        sys.stdout.flush();sys.stderr.flush();os.sync()
        libc=ctypes.CDLL(None,use_errno=True);libc.reboot(0x4321fedc)
        raise RuntimeError('guest poweroff failed')
