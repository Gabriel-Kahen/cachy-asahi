#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual owned574 capture + diskless 16 KiB CLI trial. Exact script payloads, without native package registration."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import shutil
import signal
import socket
import struct
import stat
import subprocess
import sys
import tarfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def supervise(argv,log,seconds,cap=1024**2,diagnostic=None):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    poll=selectors.DefaultSelector();data=bytearray();started=time.monotonic();natural=False;observed=False
    try:
        os.set_blocking(child.stdout.fileno(),False);poll.register(child.stdout,selectors.EVENT_READ)
        while poll.get_map() or os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            s.need(time.monotonic()-started<seconds,'owned actor deadline')
            remaining=started+seconds-time.monotonic()
            if diagnostic is not None and not observed and time.monotonic()-started>=min(60,seconds-5) and remaining>3:
                observed=True;state,collect=diagnostic
                try:state.update(collect(child,bytes(data),min(started+seconds-1,time.monotonic()+2)))
                except Exception as error:state.update(status='UNAVAILABLE',error_type=type(error).__name__,reason=str(error)[:160])
            for key,_ in poll.select(.05):
                raw=os.read(key.fd,65536)
                if not raw:poll.unregister(key.fileobj);continue
                s.need(len(data)+len(raw)<=cap,'owned actor output bound');data.extend(raw)
        natural=True
    finally:
        # The unreaped session leader pins its PID through every cleanup signal.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(child.pid,sig)
            except ProcessLookupError:pass
        code=child.wait(timeout=5);poll.close();child.stdout.close();log.write_bytes(data)
    try:os.killpg(child.pid,0)
    except ProcessLookupError:absent=True
    else:absent=False
    s.need(natural and absent,'natural actor exit and complete group retirement required')
    return code,bytes(data),dict(argv=list(map(str,argv)),exit=code,natural_exit=natural,group_absent=absent,
        seconds=round(time.monotonic()-started,6),bytes=len(data),sha256=s.sha(data))



PROGRESS=('INIT_ENTER','PROC_BEGIN','PROC_READY','DEV_BEGIN','DEV_READY','PTS_BEGIN','PTS_READY',
    'UNAME_BEGIN','UNAME_READY','PAGE_PROBE_BEGIN','PAGE_PROBE_READY','PYTHON_BEGIN','PYTHON_ENTER',
    'PAYLOAD_BEGIN','PAYLOAD_READY','UID_READY','HIGHLIGHTING_BEGIN','HIGHLIGHTING_READY',
    'SUBSTRING_BEGIN','SUBSTRING_READY','AUTOPAIR_BEGIN','AUTOPAIR_READY','MIRRORS_BEGIN','MIRRORS_READY','PYTHON_READY')


def progress(raw,nonce):
    rows=[]
    for line in raw.replace(b'\r',b'').splitlines():
        if not line.startswith(b'TOOLS16K_PROGRESS '):continue
        words=line.decode('ascii').split()
        s.need(len(words)==3 and words[1]==nonce and words[2] in PROGRESS and len(rows)<len(PROGRESS),
               'bounded exact progress diagnostic required')
        rows.append(words[2])
    s.need(len(set(rows))==len(rows) and [PROGRESS.index(x) for x in rows]==sorted(PROGRESS.index(x) for x in rows),
           'progress ordering/uniqueness differs')
    return dict(markers=rows,last=rows[-1] if rows else None,acceptance_credit=False)


def kernel_location(registers,receipt,config):
    found=re.findall(r'(?:^|\s)PC=(?:0x)?([0-9a-fA-F]{8,16})(?:\s|$)',registers)
    if len(found)!=1:return dict(status='NO_UNIQUE_PC')
    pc=int(found[0],16)
    if 'CONFIG_RANDOMIZE_BASE=y' in config.splitlines():return dict(status='KASLR_NOT_SYMBOLIZED',PC=hex(pc))
    if not any(line in config.splitlines() for line in ('# CONFIG_RANDOMIZE_BASE is not set','CONFIG_RANDOMIZE_BASE=n')):
        return dict(status='KASLR_STATE_UNCONFIRMED',PC=hex(pc))
    path=Path(receipt['config']['path']).with_name('System.map');row=receipt['system_map']
    s.need(path==Path(row['path']),'exact completed kernel symbol-map path required')
    raw=s.read(path,2*1024**2);s.need(len(raw)==row['bytes'] and s.sha(raw)==row['sha256'],'actual symbol map differs')
    symbols=[]
    for line in raw.decode('ascii').splitlines():
        fields=line.split();s.need(len(fields)==3 and re.fullmatch('[0-9a-fA-F]{8,16}',fields[0]),'symbol map row differs')
        symbols.append((int(fields[0],16),fields[1],fields[2]))
    s.need(len(symbols)<=100000 and symbols==sorted(symbols,key=lambda x:x[0]),'bounded ordered kernel symbols required')
    lower=[row for row in symbols if row[0]<=pc];upper=[row for row in symbols if row[0]>pc]
    if not lower or not upper:return dict(status='PC_OUTSIDE_SYMBOL_MAP',PC=hex(pc),map_sha256=s.sha(raw))
    return dict(status='NEAREST_SYMBOL_ONLY_NOT_CALLSTACK',PC=hex(pc),map_sha256=s.sha(raw),KASLR='DISABLED',
        lower=[dict(address=hex(a),type=t,name=n,offset=pc-a) for a,t,n in lower[-3:]],
        upper=[dict(address=hex(a),type=t,name=n) for a,t,n in upper[:2]])


def vm_observation(child,path,receipt,config,raw,nonce,deadline):
    result=dict(status='UNAVAILABLE',acceptance_credit=False,progress=progress(raw,nonce))
    info=path.lstat();s.need(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() and
        not any(p.is_symlink() for p in (path,*path.parents)),'exact private QMP socket required')
    s.need(os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None,'live unreaped QEMU required')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        pending=b'';total=0;messages=0
        def bound():
            remaining=deadline-time.monotonic();s.need(remaining>0,'QMP observation deadline');stream.settimeout(min(.5,remaining))
        bound();stream.connect(str(path))
        peer=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        s.need(peer==(child.pid,os.getuid(),os.getgid()),'QMP peer is not the exact owned QEMU')
        def receive():
            nonlocal pending,total,messages
            while b'\n' not in pending:
                bound();part=stream.recv(4096);s.need(part,'QMP observation EOF');total+=len(part)
                s.need(total<=65536,'whole QMP observation byte bound');pending+=part
            line,pending=pending.split(b'\n',1);messages+=1;s.need(messages<=24,'QMP observation message bound')
            value=json.loads(line);s.need(type(value) is dict,'QMP object required');return value
        s.need(type(receive().get('QMP')) is dict,'QMP greeting required')
        def call(name,identifier,arguments=None):
            value=dict(execute=name,id=identifier)
            if arguments is not None:value['arguments']=arguments
            bound();stream.sendall((json.dumps(value)+'\n').encode())
            while True:
                response=receive()
                if 'event' in response:continue
                s.need(response.get('id')==identifier and 'return' in response and 'error' not in response,'exact QMP response required')
                return response['return']
        call('qmp_capabilities',1)
        result.update(peer=dict(pid=peer[0],uid=peer[1],gid=peer[2]),qemu_status=call('query-status',2),
            cpus=call('query-cpus-fast',3))
        registers=call('human-monitor-command',4,dict(command_line='info registers'))
        s.need(type(registers) is str and len(registers.encode())<=16384,'bounded read-only register response required')
        result.update(status='READ_ONLY_OWNED_QEMU_OBSERVED',registers=registers)
        try:result['kernel_location']=kernel_location(registers,receipt,config)
        except Exception as error:result['kernel_location']=dict(status='UNAVAILABLE',error_type=type(error).__name__,reason=str(error)[:160])
        s.need(os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None,'QEMU exited during observation')
        s.need(len(json.dumps(result).encode())<=65536,'whole VM observation receipt bound')
    return result


def uart_observation(raw,nonce):
    s.need(len(raw)<=1024**2,'existing UART bound')
    report=dict(bytes=len(raw),sha256=s.sha(raw),progress=progress(raw,nonce),acceptance_credit=False)
    samples=[(0,raw)] if len(raw)<=65536 else [(0,raw[:8192]),(len(raw)-8192,raw[-8192:])]
    report['samples']=[dict(offset=offset,bytes=len(data),sha256=s.sha(data),base64=base64.b64encode(data).decode()) for offset,data in samples]
    report['complete']=len(raw)<=65536;return report


def terminal_observation(value,case,receipt):
    """Diagnostic-only joins; never supplies guest/fixture acceptance credit."""
    s.need(type(value) is dict and value.get('schema_version')==1 and value.get('case')==case and
        value.get('acceptance_credit') is False and value.get('observer_reaping')==value.get('observer_signals')=='NONE' and
        value.get('fixture_sha256')==receipt['files']['fixtures/substring.py']['sha256'] and
        value.get('observer_sha256')==receipt['files']['fixtures/substring_observer.py']['sha256'],
        'terminal observation source/case/scope differs')
    if case=='noninteractive':
        s.need(value.get('status')=='NO_PTY_ORIGINAL_NONINTERACTIVE_CASE','original noninteractive observation differs');return
    integer=lambda n:type(n) is int and 0<=n<2**63
    pid=lambda n:type(n) is int and 1<n<2**31
    s.need(value.get('status')=='TERMINAL_OBSERVATION_ONLY' and pid(value.get('pid')) and pid(value.get('parent_pid')) and
        value.get('uid')==value.get('gid')==23001 and type(value.get('clock_ticks')) is int and 0<value['clock_ticks']<=100000,
        'bounded terminal identity/clock required')
    events=value.get('events');stages=('WAIT_FAILURE_BEFORE_ORIGINAL_CLOSE','BEFORE_ORIGINAL_CLOSE','AFTER_ORIGINAL_CLOSE')
    s.need(type(events) is list and len(events)<=3 and all(e.get('stage') in stages for e in events) and
        [stages.index(e['stage']) for e in events]==sorted(set(stages.index(e['stage']) for e in events)),
        'fixed ordered terminal observations required')
    for event in events:
        if event['stage']=='WAIT_FAILURE_BEFORE_ORIGINAL_CLOSE':
            s.need(integer(event.get('wait_elapsed_ns')) and event['wait_elapsed_ns']<=180*10**9 and
                (event.get('original_read_return') is None or type(event['original_read_return']) is bool) and
                type(event.get('original_read_calls')) is int and 0<=event['original_read_calls']<=1000000 and
                type(event.get('error_type')) is str and type(event.get('reason')) is str and len(event['reason'])<=96,
                'bounded original wait failure observation required')
    points=[value['initial']]+([value['last_wait_before']] if 'last_wait_before' in value else [])+events
    starts=set();original_code=None;peeked_code=None;elapsed=-1
    for point in points:
        s.need(integer(point.get('elapsed_ns')) and (point.get('returncode') is None or type(point['returncode']) is int),
            'terminal elapsed/status required')
        s.need(point['elapsed_ns']>=elapsed,'terminal observation time moved backwards');elapsed=point['elapsed_ns']
        if original_code is not None:s.need(point['returncode']==original_code,'original terminal returncode changed after reaping')
        if point['returncode'] is not None:
            original_code=point['returncode']
            if peeked_code is not None:s.need(original_code==peeked_code,'non-reaping and original terminal exit disagree')
        status=point.get('status')
        s.need(status in ('ORIGINAL_ALREADY_REAPED','OBSERVED_UNREAPED_CHILD','UNAVAILABLE'),'terminal observation status differs')
        if status=='ORIGINAL_ALREADY_REAPED':s.need(type(point['returncode']) is int,'original reaped status absent');continue
        if status=='UNAVAILABLE':continue
        node=point['proc'];starts.add(node['start'])
        s.need(point['returncode'] is None and node['pid']==node['pgid']==node['sid']==value['pid'] and
            node['ppid']==value['parent_pid'] and point['uid']==point['gid']==[23001]*4 and
            all(integer(node[k]) for k in ('utime','stime','start')) and type(node['state']) is str and len(node['state'])==1 and
            type(point['cpu_limit']) is list and len(point['cpu_limit'])==2 and all(integer(n) for n in point['cpu_limit']),
            'original terminal PID/start/UID/CPU identity differs')
        waited=point.get('waitid')
        if waited is not None:
            s.need(type(waited) is dict and set(waited)=={'code','status'} and waited['code'] in (1,2,3) and
                type(waited['status']) is int and (0<=waited['status']<=255 if waited['code']==1 else 1<=waited['status']<=64),
                'non-reaping terminal exit observation differs')
            observed=waited['status'] if waited['code']==1 else -waited['status']
            s.need(peeked_code in (None,observed),'non-reaping terminal exit changed');peeked_code=observed
    s.need(len(starts)<=1,'terminal child starttime changed')


def failed_substring_diagnostic(output,nonce,release,receipt):
    s.need(len(output)<=1024**2,'bounded UART diagnostic required')
    rows=[line[len(b'TOOLS16K_DIAGNOSTIC '):] for line in output.replace(b'\r',b'').splitlines() if line.startswith(b'TOOLS16K_DIAGNOSTIC ')]
    if not rows:return None
    s.need(len(rows)==1 and len(rows[0])<=65536,'one bounded substring diagnostic required')
    value=json.loads(rows[0]);names=('noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist')
    argv=['/usr/bin/python3','-I','-B','/fixtures/substring_observer.py','--module-dir',
        '/usr/share/cachy-asahi/zsh-history-substring-search','--work','/tmp/tools16k/substring',
        '--highlight-wrapper','/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh']
    identities=('guest.py','fixtures/substring.py','fixtures/substring_observer.py','usr/bin/zsh',
        'usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh',
        'usr/share/cachy-asahi/zsh-history-substring-search/zsh-history-substring-search.zsh',
        'usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh')
    s.need(value['schema_version']==1 and value['status']=='SUBSTRING_FAILURE_DIAGNOSTIC_ONLY' and
        value['acceptance_credit'] is False and value['nonce']==nonce and value['kernel']==release and
        value['architecture']=='aarch64' and value['page_size']==16384 and value['uid']==value['gid']==[23001]*3 and value['groups']==[] and
        value['source_commit']==receipt['source_commit'] and value['payload_manifest_sha256']==s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()) and
        value['identities']=={n:receipt['files'][n] for n in identities} and value['argv']==argv and
        value['product_change']=='NONE' and value['rerun']=='NOT_RUN','substring diagnostic identity/scope differs')
    s.need(set(value['cases'])==set(names),'all six fixed substring case observations required')
    samples=[(value['original_receipt'],16384)]
    for case in value['cases'].values():
        present=case['snapshot_numbers_present'];latest=case['latest_snapshot'];files=case['files']
        s.need(type(present) is list and all(type(n) is int and 1<=n<=10 for n in present) and present==sorted(set(present)) and
            latest==(present[-1] if present else None) and {'terminal.log','ready','prompt-sequence','terminal-exit.json'}<=set(files)<=
            {'terminal.log','ready','prompt-sequence','latest_snapshot','terminal-exit.json'},'bounded fixed substring file allowlist required')
        samples.extend((row,1536 if leaf=='terminal.log' else 4096 if leaf=='latest_snapshot' else 3072 if leaf=='terminal-exit.json' else 64) for leaf,row in files.items())
    command=value.get('command')
    if command is not None:
        s.need(command['argv']==argv and command['expected_exit']==0 and command['natural_exit'] is True and
            type(command['exit']) is int and type(command['group_absent']) is bool and
            (command['exit']!=0 or command['group_absent'] is False) and
            type(command['pid']) is int and command['pid']>0 and command['pgid']==command['pid'],
            'original failed substring command/group required')
        for name in ('stdout','stderr'):
            row=value[name];s.need(row['bytes']==command[name+'_bytes'] and row['sha256']==command[name+'_sha256'],
                'original command output/sample join differs');samples.append((row,1024))
    for row,limit in samples:
        if row.get('status') in ('ABSENT','UNAVAILABLE'):continue
        raw=base64.b64decode(row['sample_base64'],validate=True)
        s.need(type(row['bytes']) is int and 0<=row['bytes']<=131072 and len(raw)<=limit and s.sha(raw)==row['sample_sha256'] and
            type(row['sample_offset']) is int and 0<=row['sample_offset']<=row['bytes'] and row['sample_offset']+len(raw)<=row['bytes'] and
            type(row['sample_complete']) is bool and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'bounded hashed substring diagnostic sample required')
        if row.get('status')=='FILE':s.need(row['uid']==23001 and row['gid']==23001,'private diagnostic file identity differs')
        if row['sample_complete']:s.need(row['sample_offset']==0 and len(raw)==row['bytes'] and s.sha(raw)==row['sha256'],
            'complete substring diagnostic bytes/hash differ')
    original=value['original_receipt'];decoded=None
    if original.get('status')=='FILE' and original['sample_complete']:
        decoded=json.loads(base64.b64decode(original['sample_base64'],validate=True))
    terminal_exit={}
    for name,case in value['cases'].items():
        row=case['files'].get('terminal-exit.json',{})
        if row.get('status')!='FILE':continue
        s.need(row['sample_complete'] and row['bytes']<=3072,'complete bounded terminal observation required')
        observation=json.loads(base64.b64decode(row['sample_base64'],validate=True))
        terminal_observation(observation,name,receipt);terminal_exit[name]=observation
    return dict(value=value,fixture_receipt=decoded,terminal_exit=terminal_exit,bytes=len(rows[0]),sha256=s.sha(rows[0]),acceptance_credit=False)


def query(argv):
    row=subprocess.run(list(map(str,argv)),capture_output=True,timeout=25)
    s.need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=65536,'bounded local query failed')
    return row.stdout.decode().strip()


def preflight(args):
    s.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','explicit disposable native CI required')
    s.need(not any(k.startswith('DOCKER_') for k in os.environ),'local default Docker only')
    s.need(s.HERE==args.source_root/'scripts/ci/tools-generic16k','adopted source location required')
    s.need(re.fullmatch('[0-9a-f]{40}',args.source_commit) and re.fullmatch('[0-9a-f]{16}',args.job_token),'source/job identity required')
    s.need(query(['git','-C',args.source_root,'rev-parse','HEAD'])==args.source_commit,'immutable checkouts differ')
    s.need(query(['docker','context','show'])=='default','local default Docker required')
    context=json.loads(query(['docker','context','inspect','default']))
    s.need(len(context)==1 and context[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local Docker socket required')
    base=json.loads(s.read(args.base_dir/'report.json'))
    s.need(base['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base['packages']==574 and base['acquired']==1153 and
           base['native_build']=='PASS' and base['build_returncode']==0 and base['failures']==[] and
           base['ownership']['token']==args.job_token and base['ownership']['build_complete'] is True and
           base['ownership']['probe_complete'] is True,'exact owned574 result required')
    image=(args.base_dir/'image-id').read_text().strip()
    s.need(image==base['image'] and s.sha(s.read(args.base_dir/'installed-packages.lock'))==s.LOCK and
           s.sha(s.read(args.base_dir/'context/expected-packages.lock'))==s.LOCK,'owned574 image/inventory differs')
    owner=s.load(args.source_root,'scripts/ci/maintained_desktop574.py')
    s.need(owner.inspect_image(image,args.job_token)['Id']==image,'owned image identity differs')
    return image,owner


def payload(archive,receipt,generic):
    s.need(receipt['status']=='CAPTURED_UNPACKED_NATIVE574_PAYLOAD' and receipt['inventory_sha256']==s.LOCK and
           receipt['payload_map_sha256']==s.MAP_SHA and receipt['products']==s.mapping()['products'] and
           s.sha(s.read(archive,270*1024**2))==receipt['archive']['sha256'] and
           archive.stat().st_size==receipt['archive']['bytes'],'captured payload identity differs')
    files={};total=0;elf_names=set()
    with tarfile.open(archive,'r:') as stream:
        for entry in stream:
            name=entry.name
            s.need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and
                   name not in files and entry.isfile() and entry.uid==entry.gid==0 and
                   len(files)<4096 and entry.size<=64*1024**2,'payload member refused')
            row=receipt['files'].get(name);s.need(row and row['bytes']==entry.size and row['mode']==entry.mode,'payload member differs')
            data=stream.extractfile(entry).read();total+=len(data)
            s.need(total<=256*1024**2 and s.sha(data)==row['sha256'],'payload hash/total differs')
            if data.startswith(b'\x7fELF'):
                elf_names.add(name)
                interpreter,needed=s.aligned(data,generic)
                s.need(receipt['elf'][name]==dict(interpreter=interpreter,needed=needed),'captured ELF view differs')
            files[name]=(stat.S_IFREG|entry.mode,data)
    s.need(set(files)==set(receipt['files']),'closed captured payload required')
    required={'guest.py',*[ 'usr/bin/'+name for name in s.TOOLS]}
    required.update(name for product in receipt['products'].values() for name in product['payload'])
    required.update(s.mapping()['fixtures'])
    s.need(required<=set(files) and elf_names==set(receipt['elf']),'complete product/tool ELF roots required')
    for name,expected in {**{n:r for product in receipt['products'].values() for n,r in product['payload'].items()},**s.mapping()['fixtures']}.items():
        mode,data=files[name]
        s.need(stat.S_IMODE(mode)==expected['mode'] and len(data)==expected['bytes'] and s.sha(data)==expected['sha256'],
               'actual captured bytes differ from explicit source payload: '+name)
    for row in receipt['elf'].values():
        s.need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,'closed interpreter absent')
        s.need(all(any(folder+lib in files for folder in ('usr/lib/','lib/')) for lib in row['needed']),'DT_NEEDED closure absent')
    return files


def kernel(receipt,root):
    s.need(receipt['profile']=='TOOLS16K_PTY_DERIVED_DIAGNOSTIC' and
           receipt['derivation']==dict(base_helper_sha256=s.pins()['files']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
               diagnostic_extension='CONFIG_UNIX98_PTYS=y;CONFIG_EVENTFD=y;CONFIG_FILE_LOCKING=y',
               workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profile_modified=False) and receipt['status']=='BUILT_ONLY' and receipt['kernel_build']=='PASS' and receipt['boot_diagnostics'] is True and
           receipt['image_check']['header_page_size']==16384 and receipt['module_policy']['CONFIG_MODULES']=='n' and
           receipt['archive']['sha256']=='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad' and
           receipt['source_commit']=='94fb23346d522edf53722357c426a3e58030beea' and
           receipt['helper']['sha256']==s.sha(s.read(s.HERE/'build_kernel.py')),
           'separately derived PTY diagnostic16K kernel receipt required')
    image=Path(receipt['image']['path']);config=Path(receipt['config']['path'])
    s.need(image.stat().st_size==receipt['image']['bytes']<=256*1024**2 and
           s.sha(s.read(image,256*1024**2))==receipt['image']['sha256'] and
           s.sha(s.read(config,65536))==receipt['config']['sha256'],'kernel Image/config identity differs')
    helper=s.load(root,'scripts/ci/tools-generic16k/build_kernel.py')
    s.need(receipt['fragment']['sha256']==s.sha(s.read(s.HERE/'kernel.fragment')) and
           receipt['diagnostic_fragment']['sha256']==s.sha(s.read(s.HERE/'kernel.fragment')+helper.DIAGNOSTIC_FRAGMENT.encode()),
           'separate base/derived PTY fragment identity differs')
    helper.config_check(config,True);helper.image_check(image);return image


def init(nonce,release):
    s.need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}',release),'guest marker identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C PYTHONDONTWRITEBYTECODE=1
fail() {{ printf 'TOOLS16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
progress() {{ printf 'TOOLS16K_PROGRESS {nonce} %s\\n' \"$1\"; }}
progress INIT_ENTER
progress PROC_BEGIN
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc || fail
progress PROC_READY
progress DEV_BEGIN
/usr/bin/mount -t devtmpfs -o nosuid devtmpfs /dev || fail
progress DEV_READY
/usr/bin/mkdir -m 0755 /dev/pts || fail
progress PTS_BEGIN
/usr/bin/mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts || fail
/usr/bin/rm -f /dev/ptmx || fail
/usr/bin/ln -s pts/ptmx /dev/ptmx || fail
/usr/bin/ln -s /proc/self/fd /dev/fd || fail
progress PTS_READY
progress UNAME_BEGIN
machine=$(/usr/bin/uname -m) || fail
release=$(/usr/bin/uname -r) || fail
page=$(/usr/bin/getconf PAGESIZE) || fail
printf 'UNAME16K %s %s\\nGETCONF16K %s\\n' "$machine" "$release" "$page"
[[ "$machine" == aarch64 && "$release" == '{release}' && "$page" == 16384 ]] || fail
progress UNAME_READY
progress PAGE_PROBE_BEGIN
/smoke || fail
progress PAGE_PROBE_READY
progress PYTHON_BEGIN
/usr/bin/python3 -I -B /guest.py '{nonce}' '{release}' || fail
progress PYTHON_READY
printf 'TOOLS16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def guest_report(output,code,nonce,release,receipt):
    s.need(code==0 and len(output)<=1024**2 and not any(message in output for message in
           (b'TOOLS16K FAIL',b'TOOLS16K_ERROR',b'TOOLS16K_DIAGNOSTIC',b'Kernel panic',b'Attempted to kill init')),
           'natural bounded guest exit0 required')
    lines=output.replace(b'\r',b'').splitlines();markers=[f'UNAME16K aarch64 {release}'.encode(),b'GETCONF16K 16384',
        b'SMOKE16K: mmap,mprotect,file-offset PASS',f'TOOLS16K PASS {nonce}'.encode()]
    s.need(all(lines.count(x)==1 for x in markers),'exact actual16K markers required')
    positions=[lines.index(x) for x in markers];s.need(positions==sorted(positions),'marker ordering differs')
    reports=[(i,line.removeprefix(b'TOOLS16K_REPORT ')) for i,line in enumerate(lines) if line.startswith(b'TOOLS16K_REPORT ')]
    s.need(len(reports)==1 and positions[2]<reports[0][0]<positions[3] and len(reports[0][1])<=65536,'one bounded guest report required')
    value=json.loads(reports[0][1])
    s.need(value['status']=='PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY' and value['nonce']==nonce and
           value['architecture']=='aarch64' and value['page_size']==16384 and value['kernel']==release and value['uid']==23001 and
           value['config_preserved'] is True and value['payload_preserved'] is True and value['owned_processes_absent'] is True and
           value['package_registration']=='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY' and
           value['GUI']==value['hardware']==value['performance']=='NOT_RUN' and value['release_admission'] is False and
           value['payload_manifest_sha256']==s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()),'guest identity/preservation/scope differs')
    fixtures=value['fixtures'];highlight=fixtures['highlighting'];substring=fixtures['substring'];fish=fixtures['autopair']
    s.need(set(fixtures)=={'highlighting','substring','autopair'} and highlight['status']=='PASS_INSTALLED_ZLE' and
           highlight['natural_exit']==0 and len(highlight['snapshots'])==2 and all(highlight[k] is True for k in
           ('noninteractive_noop','preexisting_module_wins','repeated_source','custom_binding_preserved','unknown_token_highlight')),
           'complete actual highlighting evidence required')
    cases=substring['tests'];s.need(substring['status']=='PASS_HOST_ZSH_PTY_CONTROLS' and substring['host_architecture']=='aarch64' and
           [r['name'] for r in cases]==['noninteractive','editing','preexisting-function','preexisting-widget','preexisting-private','coexist'] and
           all(r['status']=='PASS' and r['exit']==0 for r in cases) and all(len(cases[i]['snapshots'])==10 for i in (1,5)) and
           substring['wrapper_sha256']==receipt['files']['usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh']['sha256'],
           'all six exact substring PTY cases required')
    fc=fish['cases'];s.need(fish['status']=='PASS' and fish['platform']=='aarch64' and fish['fish']=='fish, version 4.9.3' and
           set(fc)=={'noninteractive','default','vi','hybrid','custom-key','custom-prefix','custom-generic','custom-tab','preset-key',
                     'existing-function','existing-autoload','existing-variable','custom-keymap','existing-wrapper'} and
           all(r['exit']==0 for r in fc.values()) and all(len(fc[n]['snapshots'])==19 and fc[n]['activation']=='enabled' for n in ('default','vi','hybrid')) and
           sum(len(r.get('snapshots',[])) for r in fc.values())==57 and
           fish['wrapper_sha256']==receipt['files']['usr/share/cachy-asahi/fish-autopair/opt-in.fish']['sha256'],
           'all fourteen real Fish cases/57 editor snapshots required')
    mirrors=value['mirrors'];s.need(mirrors['version']=='0.2.0' and mirrors['network']=='NOT_USED' and
           mirrors['conflict_journal_phase']=='ACTIVE' and all(mirrors[k] is True for k in
           ('restored_bytes_mode_uid_gid','retry_preserved','edited_target_preserved')) and
           all(re.fullmatch('[0-9a-f]{64}',mirrors[k]) for k in ('catalog_sha256','candidate_sha256','original_sha256')),
           'actual private mirror activation/restoration/conflict evidence required')
    expected_catalog=dict(schema_version=1,architecture='aarch64',base='asahi-alarm',repository='core',
        database=dict(bytes=1,sha256=s.sha(b'x')),mirrors=[dict(id='private',server='https://example.invalid/$arch/$repo')])
    catalog_sha=s.sha((json.dumps(expected_catalog,sort_keys=True)+'\n').encode())
    candidate=('# Separate candidate; selected repository: core\n# Exact catalog SHA256: '+catalog_sha+
        '\nServer = https://example.invalid/$arch/$repo\n').encode()
    s.need(mirrors['catalog_sha256']==catalog_sha and mirrors['candidate_sha256']==s.sha(candidate) and
           mirrors['original_sha256']==s.sha(b'# preserve caller mirror bytes\nServer = https://original.invalid/$arch/$repo\n'),
           'mirror controlled catalog/candidate/prior bytes differ')
    commands=value['commands'];s.need(len(commands)==11,'finite eleven command set required')
    work='/tmp/tools16k';prefix=['/usr/bin/python3','-I','-B'];mirror='/usr/bin/cachy-asahi-mirrors'
    paths=work+'/mirrors/';activate=[mirror,'activate',paths+'catalog.json','--candidate',paths+'candidate','--repository','core','--target',paths+'mirrorlist','--state']
    restore=[mirror,'restore','--repository','core','--target',paths+'mirrorlist','--state']
    expected=[prefix+['/fixtures/highlighting.py',work+'/highlighting'],prefix+['/fixtures/substring_observer.py','--module-dir',
        '/usr/share/cachy-asahi/zsh-history-substring-search','--work',work+'/substring','--highlight-wrapper',
        '/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh'],prefix+['/fixtures/autopair.py','--source',
        '/usr/share/cachy-asahi/fish-autopair','--output',work+'/autopair'],[mirror,'--version'],[mirror,'check',paths+'catalog.json'],
        activate+[paths+'journal.json'],activate+[paths+'journal.json'],restore+[paths+'journal.json'],restore+[paths+'journal.json'],
        activate+[paths+'conflict.json'],restore+[paths+'conflict.json']]
    for i,(row,argv) in enumerate(zip(commands,expected)):
        s.need(row['argv']==argv and row['exit']==(1 if i==10 else 0) and row['group_absent'] is True and
               row['owned_processes_absent'] is True and 0<=row['seconds']<=(185 if i<3 else 35) and
               0<=row['stdout_bytes']+row['stderr_bytes']<=131072 and
               all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('stdout_sha256','stderr_sha256')),'exact command/result/group differs')
    s.need(commands[3]['stdout_sha256']==s.sha(b'cachy-asahi-mirrors 0.2.0\n'),'actual mirror version output differs')
    return value


def capture_command(args,image,name,capture):
    return ['docker','run','--rm','--name',name,'--cidfile',str(args.private/'capture.cid'),'--pull=never','--platform=linux/arm64',
        '--label','org.cachy-asahi.tools16k.job='+args.job_token,'--user',f'{os.getuid()}:{os.getgid()}',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=128','--memory=2g','--cpus=2',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--env','CACHY_TOOLS16K_CAPTURE=1','--env','PYTHONDONTWRITEBYTECODE=1',
        '--mount','type=bind,src='+str(s.HERE)+',dst=/source,readonly',
        '--mount','type=bind,src='+str(args.source_root)+',dst=/repo,readonly',
        '--mount','type=bind,src='+str(args.base_dir/'installed-packages.lock')+',dst=/expected.lock,readonly',
        '--mount','type=bind,src='+str(capture)+',dst=/out','--entrypoint=/usr/bin/python3',image,'-I','-B','/source/capture.py','--image-id',image,'--source-commit',args.source_commit]


def retire(args,name,image,started):
    result=dict(capture_absent=not started,private_removed=False,producer='BORROWED_PRESERVED')
    if started:
        cid=s.read(args.private/'capture.cid',128).decode().strip();s.need(re.fullmatch('[0-9a-f]{64}',cid),'capture CID required')
        found=query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'])
        s.need(found in ('',name),'capture name ambiguous')
        if found:
            rows=json.loads(query(['docker','container','inspect',cid]));s.need(len(rows)==1,'one owned capture required');row=rows[0]
            s.need(row['Id']==cid and row['Name']=='/'+name and row['Image']==image and
                   row['Config']['Labels'].get('org.cachy-asahi.tools16k.job')==args.job_token,'capture ownership differs')
            query(['docker','rm','-f',cid])
        s.need(not query(['docker','container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}']) and
               not query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'capture still present')
        result['capture_absent']=True
    shutil.rmtree(args.private);result['private_removed']=not args.private.exists();return result


def trial(args):
    s.check_source(args.source_root);products=s.products(args.source_root)
    if not args.execute:return dict(status='SOURCE_INPUTS_VERIFIED_NOT_EXECUTED',products=products)
    image,owner=preflight(args)
    for path in (args.private,args.output):
        s.need(path.is_absolute() and not path.exists() and not any(p.is_symlink() for p in (path,*path.parents)) and
               not any(path.is_relative_to(p) or p.is_relative_to(path) for p in (args.source_root,args.base_dir)),
               'fresh separate ordinary work required')
    s.need(not args.private.is_relative_to(args.output) and not args.output.is_relative_to(args.private),'private/public separation required')
    os.umask(0o077);args.private.mkdir(mode=0o700);args.output.mkdir(mode=0o700)
    generic=s.load(args.source_root,'scripts/virtual/generic16k/fixture.py')
    report=dict(status='FAIL',scope=s.SCOPE,source_commit=args.source_commit,job_token=args.job_token,image_id=image,
        payload_map_sha256=s.MAP_SHA,products=products,GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False,producer_cleanup='PENDING',actors=[])
    name='tools16k-capture-'+args.job_token;started=False
    try:
        s.need(not query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'fresh capture name required')
        capture=args.private/'capture';capture.mkdir(mode=0o700);started=True
        code,_,actor=supervise(capture_command(args,image,name,capture),args.private/'capture.log',240)
        report['actors'].append(actor)
        s.need(code==0,'native byte capture failed');raw=s.read(capture/'capture.json');receipt=json.loads(raw)
        s.need(receipt['image_id']==image and receipt['source_commit']==args.source_commit and receipt['products']==products,'capture product/image join differs')
        report['capture']=receipt;files=payload(capture/'payload.tar',receipt,generic)
        kr=json.loads(s.read(args.kernel_receipt,65536));image_path=kernel(kr,args.source_root)
        report['kernel']=kr;report['kernel_config']=s.read(Path(kr['config']['path']),65536).decode()
        copied=args.private/'Image';shutil.copyfile(image_path,copied);s.need(s.sha(s.read(copied,256*1024**2))==kr['image']['sha256'],'copied Image differs')
        smoke=args.private/'smoke';clang=shutil.which('clang');linker=shutil.which('ld.lld');qemu=shutil.which('qemu-system-aarch64')
        s.need(clang and linker and qemu,'accepted fixture tools required')
        smoke_source=args.source_root/'scripts/virtual/generic16k/smoke.c'
        argv=[clang,'--target=aarch64-linux-gnu','-nostdlib','-static','-fuse-ld='+linker,'-O2','-fno-stack-protector','-fno-builtin',
              '-Wl,-z,max-page-size=16384','-Wl,-e,_start',str(smoke_source),'-o',str(smoke)]
        code,_,actor=supervise(argv,args.private/'compile.log',60);report['actors'].append(actor)
        s.need(code==0,'unchanged page probe build failed')
        binary=s.read(smoke);s.aligned(binary,generic);nonce=secrets.token_hex(16);release=kr['kernel_release']
        files.update({'init':(stat.S_IFREG|0o755,init(nonce,release)),'smoke':(stat.S_IFREG|0o755,binary),
            'payload.json':(stat.S_IFREG|0o644,raw),'page-data':(stat.S_IFREG|0o444,b'A'*16384+b'B'*16384),
            'etc/passwd':(stat.S_IFREG|0o644,b'root:x:0:0:private init:/tmp:/usr/bin/bash\nfixture:x:23001:23001:private tool fixture:/tmp/tools16k/user:/usr/bin/bash\n'),
            'etc/group':(stat.S_IFREG|0o644,b'root:x:0:\nfixture:x:23001:\n'),
            'etc/nsswitch.conf':(stat.S_IFREG|0o644,b'passwd: files\ngroup: files\n'),
            'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')})
        ramfs=args.private/'initramfs.cpio';ramfs.write_bytes(generic.cpio(files))
        report['boot_inputs']=dict(nonce=nonce,init=dict(mode=stat.S_IMODE(files['init'][0]),bytes=len(files['init'][1]),sha256=s.sha(files['init'][1]),text=files['init'][1].decode()),
            payload_manifest=dict(bytes=len(raw),sha256=s.sha(raw)),initramfs=dict(bytes=ramfs.stat().st_size,sha256=s.sha(s.read(ramfs,300*1024**2))),
            captured_python=receipt['files']['usr/bin/python3'],guest_script=receipt['files']['guest.py'])
        argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(copied),
              '-initrd',str(ramfs),'-append',generic.boot_arguments(True)+' tools16k=1',
              '-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot',
              '-qmp','unix:'+str(args.private/'qmp.sock')+',server=on,wait=off']
        report.update(qemu_argv=argv,qemu_argv_sha256=s.sha((json.dumps(argv,separators=(',',':'))+'\n').encode()),tools={n:s.sha(s.read(p,64*1024**2)) for n,p in (('clang',Path(clang).resolve()),('ld.lld',Path(linker).resolve()),('qemu',Path(qemu).resolve()))},
                      initramfs_sha256=s.sha(s.read(ramfs,300*1024**2)),page_probe_sha256=s.sha(binary))
        report['vm_observation']=dict(status='NOT_ATTEMPTED',acceptance_credit=False)
        diagnostic=(report['vm_observation'],lambda child,raw,deadline:vm_observation(child,args.private/'qmp.sock',kr,report['kernel_config'],raw,nonce,deadline))
        code,uart,actor=supervise(argv,args.private/'uart.log',900,diagnostic=diagnostic);report['actors'].append(actor)
        report.update(guest=guest_report(uart,code,nonce,release,receipt),natural_VM_exit=True,QEMU_exit=code,
                      uart=dict(bytes=len(uart),sha256=s.sha(uart)),status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT')
    except BaseException as error:
        report.update(status='FAIL',error_type=type(error).__name__,reason=str(error)[:256])
    finally:
        report['log_tails']={}
        try:
            for filename in ('capture.log','compile.log','uart.log'):
                path=args.private/filename
                if path.exists():
                    data=s.read(path,1024**2);tail=data[-8192:]
                    report['log_tails'][filename]=dict(bytes=len(data),tail_sha256=s.sha(tail),tail_base64=base64.b64encode(tail).decode())
                    if filename=='uart.log' and 'boot_inputs' in report:
                        report['uart_observation']=uart_observation(data,report['boot_inputs']['nonce'])
                        diagnostic=failed_substring_diagnostic(data,report['boot_inputs']['nonce'],report['kernel']['kernel_release'],report['capture'])
                        if diagnostic is not None:report['failed_substring_diagnostic']=diagnostic
        except BaseException as error:report.update(status='FAIL',log_export_error=type(error).__name__)
        old=signal.getsignal(signal.SIGALRM)
        def expired(*_):raise TimeoutError('owned consumer cleanup deadline')
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,90)
        try:
            report['consumer_cleanup']=retire(args,name,image,started)
            s.need(owner.inspect_image(image,args.job_token)['Id']==image,'borrowed producer image changed')
        except BaseException as error:report.update(status='FAIL',cleanup_error=type(error).__name__)
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
        s.save(args.output/'runtime.json',report)
    return report


def finalize(args):
    report=json.loads(s.read(args.output/'runtime.json',2*1024**2));base=json.loads(s.read(args.base_dir/'report.json'))
    try:
        cleanup=base['owned_cleanup'];consumer=report['consumer_cleanup']
        s.need(report['job_token']==args.job_token==base['ownership']['token'] and
               report['status']=='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT' and report['natural_VM_exit'] is True and
               report['QEMU_exit']==0 and len(report['actors'])==3 and
               all(a['natural_exit'] is True and a['exit']==0 and a['group_absent'] is True for a in report['actors']) and
               consumer['capture_absent'] is True and consumer['private_removed'] is True and
               consumer['producer']=='BORROWED_PRESERVED' and cleanup['status']=='PASS' and
               cleanup['probe']['absence_verified'] is True and cleanup['image']['absence_verified'] is True and
               cleanup['image']['id']==report['image_id'],'ordered consumer/producer cleanup required')
        work=args.kernel_work
        s.need(work==Path(os.environ['RUNNER_TEMP'])/'tools16k-kernel' and work.is_absolute() and
               not any(p.is_symlink() for p in (work,*work.parents)) and work.stat().st_uid==os.getuid() and
               Path(report['kernel']['helper']['path'])==work/'helper/build_kernel.py' and
               report['kernel']['status']=='BUILT_ONLY' and report['kernel']['kernel_build']=='PASS',
               'completed owned kernel work required')
        shutil.rmtree(work);s.need(not work.exists(),'owned kernel work remains')
        report.update(status='PASS_GENERIC_16K_MAPPED_TOOLS_PTY_CLI_ONLY',producer_cleanup=cleanup,kernel_work_removed=True)
    except BaseException as error:report.update(status='FAIL',finalize_error=type(error).__name__)
    s.save(args.output/'runtime.json',report);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('trial','finalize'))
    for name in ('base-dir','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--job-token',required=True)
    for name in ('source-root','private','kernel-receipt','kernel-work'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--source-commit');parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    def interrupted(*_):raise KeyboardInterrupt('owned16K controller interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    value=trial(args) if args.mode=='trial' else finalize(args)
    print(json.dumps(dict(status=value['status'],scope=s.SCOPE)))
    raise SystemExit(value['status']=='FAIL')
