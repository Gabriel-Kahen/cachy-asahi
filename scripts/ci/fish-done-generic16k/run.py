#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual owned574 capture + generic 16 KiB Done PTY recorder trial. No package registration."""
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
import stat
import subprocess
import sys
import tarfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def supervise(argv,log,seconds,cap=1024**2):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    poll=selectors.DefaultSelector();data=bytearray();started=time.monotonic();natural=False
    try:
        os.set_blocking(child.stdout.fileno(),False);poll.register(child.stdout,selectors.EVENT_READ)
        while poll.get_map() or os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            s.need(time.monotonic()-started<seconds,'owned actor deadline')
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


def query(argv):
    row=subprocess.run(list(map(str,argv)),capture_output=True,timeout=25)
    s.need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=65536,'bounded local query failed')
    return row.stdout.decode().strip()


def preflight(args):
    s.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','explicit disposable native CI required')
    s.need(not any(k.startswith('DOCKER_') for k in os.environ),'local default Docker only')
    s.need(s.HERE==args.source_root/'scripts/ci/fish-done-generic16k','adopted source location required')
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
    required.update((s.RECORDER,s.ADAPTED,s.SOURCE,s.ADAPTER))
    s.need(required<=set(files) and elf_names==set(receipt['elf']),'complete product/tool ELF roots required')
    for name,expected in {**{n:r for product in receipt['products'].values() for n,r in product['payload'].items()},**s.mapping()['fixtures']}.items():
        mode,data=files[name]
        s.need(stat.S_IMODE(mode)==expected['mode'] and len(data)==expected['bytes'] and s.sha(data)==expected['sha256'],
               'actual captured bytes differ from explicit source payload: '+name)
    for row in receipt['elf'].values():
        s.need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,'closed interpreter absent')
        s.need(all(any(folder+lib in files for folder in ('usr/lib/','lib/')) for lib in row['needed']),'DT_NEEDED closure absent')
    s.test_transport(receipt)
    adapter=s.load(s.HERE.parents[2],'scripts/ci/fish-done-generic16k/recorder_adapter.py')
    s.need(files[s.ADAPTED][1]==adapter.adapt(files['fixtures/done.py'][1]),
        'parent independently reproduced prepare-only adapted fixture differs')
    return files


def kernel(receipt,root):
    s.need(receipt['profile']=='TOOLS16K_PTY_DERIVED_DIAGNOSTIC' and
           receipt['derivation']==dict(base_helper_sha256=s.pins()['files']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
               diagnostic_extension='CONFIG_UNIX98_PTYS=y;CONFIG_EVENTFD=y;CONFIG_FILE_LOCKING=y',
               workspace_scan='ACTIVE_CHILD_COMPILER_OUTPUT_ENOENT_ONLY_STRICT_FINAL',accepted_profile_modified=False) and receipt['status']=='BUILT_ONLY' and receipt['kernel_build']=='PASS' and receipt['boot_diagnostics'] is True and
           receipt['image_check']['header_page_size']==16384 and receipt['module_policy']['CONFIG_MODULES']=='n' and
           receipt['archive']['sha256']=='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad' and
           receipt['source_commit']=='94fb23346d522edf53722357c426a3e58030beea' and
           receipt['helper']['sha256']==s.pins()['files']['scripts/ci/tools-generic16k/build_kernel.py']['sha256'],
           'separately derived PTY diagnostic16K kernel receipt required')
    image=Path(receipt['image']['path']);config=Path(receipt['config']['path'])
    s.need(image.stat().st_size==receipt['image']['bytes']<=256*1024**2 and
           s.sha(s.read(image,256*1024**2))==receipt['image']['sha256'] and
           s.sha(s.read(config,65536))==receipt['config']['sha256'],'kernel Image/config identity differs')
    helper=s.load(root,'scripts/ci/tools-generic16k/build_kernel.py')
    s.need(receipt['fragment']['sha256']==s.sha(s.read(Path(root)/'scripts/ci/tools-generic16k/kernel.fragment')) and
           receipt['diagnostic_fragment']['sha256']==s.sha(s.read(Path(root)/'scripts/ci/tools-generic16k/kernel.fragment')+helper.DIAGNOSTIC_FRAGMENT.encode()),
           'separate base/derived PTY fragment identity differs')
    helper.config_check(config,True);helper.image_check(image);return image


def init(nonce,release):
    s.need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}',release),'guest marker identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C PYTHONDONTWRITEBYTECODE=1
fail() {{ printf 'DONE16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc || fail
/usr/bin/mount -t devtmpfs -o nosuid devtmpfs /dev || fail
/usr/bin/mkdir -m 0755 /dev/pts || fail
/usr/bin/mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts || fail
/usr/bin/rm -f /dev/ptmx || fail
/usr/bin/ln -s pts/ptmx /dev/ptmx || fail
/usr/bin/ln -s /proc/self/fd /dev/fd || fail
machine=$(/usr/bin/uname -m) || fail
release=$(/usr/bin/uname -r) || fail
page=$(/usr/bin/getconf PAGESIZE) || fail
printf 'UNAME16K %s %s\\nGETCONF16K %s\\n' "$machine" "$release" "$page"
[[ "$machine" == aarch64 && "$release" == '{release}' && "$page" == 16384 ]] || fail
/smoke || fail
/usr/bin/python3 -I -B /guest.py '{nonce}' '{release}' || fail
printf 'DONE16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def failed_driver_diagnostic(output,nonce,release,receipt):
    s.need(len(output)<=1024**2,'bounded UART diagnostic required')
    rows=[line[len(b'DONE16K_DIAGNOSTIC '):] for line in output.replace(b'\r',b'').splitlines() if line.startswith(b'DONE16K_DIAGNOSTIC ')]
    if not rows:return None
    s.need(len(rows)==1 and len(rows[0])<=65536,'one bounded failed-driver diagnostic required')
    value=json.loads(rows[0]);s.need(value['schema_version']==1 and value['status']=='FAILED_DRIVER_DIAGNOSTIC_ONLY' and
        value['nonce']==nonce and value['kernel']==release and value['architecture']=='aarch64' and value['page_size']==16384 and value['uid']==23001 and
        value['acceptance_credit'] is False and value['product_change']=='NONE' and value['notification_manager']=='NOT_RUN' and
        value['payload_manifest_sha256']==s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()),'failed-driver diagnostic identity/scope differs')
    # Validate byte samples without turning diagnostic observations into acceptance.
    samples=[value['stdout'],value['stderr'],value['original_receipt']]
    allowed={'notifications.jsonl','terminal.log','events','load-status','setup-status','status-1','status-2','prompt-1','prompt-2','notify-mode','bin/notify-send'}
    s.need(type(value['cases']) is dict and len(value['cases'])<=2,'bounded fixed diagnostic cases required')
    for case,files in value['cases'].items():
        s.need(case in value['case_directories_present'] and set(files)==allowed,'fixed diagnostic file allowlist required');samples.extend(files.values())
    probe=value.get('foreground_probe')
    if probe is not None:
        s.need(type(probe) is dict and type(probe.get('command')) is dict,'foreground probe command required')
        row=probe['command']
        s.need(row['argv']==['/usr/bin/python3','-I','-B','/guest.py','--foreground-probe','/tmp/done16k/foreground-probe'],
               'fixed separate foreground probe argv required')
        if 'value' in probe:
            observation=probe['value'];files=observation.get('files',{})
            raw=(json.dumps(observation,sort_keys=True,separators=(',',':'))+'\n').encode()
            s.need(len(raw)<=16384 and row['stdout_bytes']==len(raw) and row['stdout_sha256']==s.sha(raw),
                   'foreground probe stdout bytes/hash differ')
            s.need(row['exit']==0 and row['expected_exit']==0 and row['natural_exit'] is True and row['group_absent'] is True and
                probe['owned_processes_absent'] is True and observation['schema_version']==1 and
                observation['status']=='FOREGROUND_PROBE_ONLY' and observation['acceptance_credit'] is False and
                observation['product_change']=='NONE' and observation['workload']=='sleep .12' and observation['threshold']==80,
                'separate diagnostic scope and retirement required')
            s.need(all(observation[field]==receipt['files'][path]['sha256'] for field,path in
                [('fixture_sha256','fixtures/done.py'),('runtime_sha256','usr/share/cachy-asahi/fish-done/done.fish'),
                 ('wrapper_sha256','usr/share/cachy-asahi/fish-done/opt-in.fish')]),'foreground probe original source identity differs')
            s.need(type(files) is dict and set(files)<= {'probe-enabled','probe-threshold','probe-exclusions','probe-completion',
                'probe-timeout-entered','probe-timeout-stderr','notifications.jsonl'},'foreground probe file allowlist required')
            samples.extend(files.values())
            transports=observation.get('transport_commands',[])
            s.need(type(transports) is list and len(transports) in (0,2),'fixed two transport observations required')
            for index,transport in enumerate(transports):
                home='/tmp/done16k/foreground-probe/transport/bin/'
                argv=([home+'timeout','--foreground','--signal=TERM','--kill-after=1s','2s','notify-send','--diagnostic-only']
                      if index==0 else [home+'notify-send','--diagnostic-only'])
                s.need(transport['kind']==('bounded-timeout' if index==0 else 'direct-recorder') and
                    transport['command']['argv']==argv and transport['command']['expected_exit']==0 and
                    re.fullmatch('[0-9a-f]{64}',transport['recorder_sha256']) and
                    type(transport['notification_count']) is int and 0<=transport['notification_count']<=2,
                    'transport observation identity differs')
                for stream in ('stdout','stderr'):
                    s.need(transport[stream]['bytes']==transport['command'][stream+'_bytes'] and
                        transport[stream]['sha256']==transport['command'][stream+'_sha256'],
                        'transport output command/sample join differs')
                samples.extend([transport['stdout'],transport['stderr']])
        else:
            samples.extend([probe['stdout'],probe['stderr']])
    for row in samples:
        if row.get('status') in ('ABSENT','UNAVAILABLE'):continue
        raw=base64.b64decode(row['sample_base64'],validate=True)
        s.need(type(row['bytes']) is int and 0<=row['bytes']<=131072 and len(raw)<=8192 and
            type(row['sample_offset']) is int and 0<=row['sample_offset']<=row['bytes'] and row['sample_offset']+len(raw)<=row['bytes'] and
            re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded diagnostic file sample required')
        if row['sample_complete']:s.need(row['sample_offset']==0 and len(raw)==row['bytes'] and s.sha(raw)==row['sha256'],'complete diagnostic bytes/hash differ')
    return dict(value=value,bytes=len(rows[0]),sha256=s.sha(rows[0]))


def guest_report(output,code,nonce,release,receipt):
    s.need(code==0 and len(output)<=1024**2 and not any(message in output for message in
           (b'DONE16K FAIL',b'DONE16K_ERROR',b'DONE16K_DIAGNOSTIC',b'Kernel panic',b'Attempted to kill init')),
           'natural bounded guest exit0 required')
    lines=output.replace(b'\r',b'').splitlines();markers=[f'UNAME16K aarch64 {release}'.encode(),b'GETCONF16K 16384',
        b'SMOKE16K: mmap,mprotect,file-offset PASS',f'DONE16K PASS {nonce}'.encode()]
    s.need(all(lines.count(x)==1 for x in markers),'exact actual16K markers required')
    positions=[lines.index(x) for x in markers];s.need(positions==sorted(positions),'marker ordering differs')
    reports=[(i,line.removeprefix(b'DONE16K_REPORT ')) for i,line in enumerate(lines) if line.startswith(b'DONE16K_REPORT ')]
    s.need(len(reports)==1 and positions[2]<reports[0][0]<positions[3] and len(reports[0][1])<=65536,'one bounded guest report required')
    value=json.loads(reports[0][1])
    s.need(value['status']==s.STATUS and value['nonce']==nonce and
           value['architecture']=='aarch64' and value['page_size']==16384 and value['kernel']==release and value['uid']==23001 and
           value['config_preserved'] is True and value['payload_preserved'] is True and value['owned_processes_absent'] is True and
           value['package_registration']=='NOT_INSTALLED_EXACT_SOURCE_PAYLOADS_COPIED_ONLY' and
           value['GUI']==value['hardware']==value['performance']==value['notification_manager']==value['DBus']==value['display']=='NOT_RUN' and
           value['notification_transport']==s.TRANSPORT and value['release_admission'] is False and
           value['payload_manifest_sha256']==s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()),'Done guest identity/preservation/scope differs')
    s.need(value['test_transport']==s.test_transport(receipt),'adapted guest/native compile payload join differs')
    proof=value['done'];cases=proof['cases']
    names={'noninteractive','foreground','background','watch-rejection','disown','repeat-preserve','command-data','transport-failure',
           'transport-timeout','disable','existing-function','existing-autoload','existing-variable','existing-wrapper','existing-public',
           'no-bus','notify-send','timeout'}
    enabled={'foreground','background','watch-rejection','disown','repeat-preserve','command-data','transport-failure','transport-timeout','disable'}
    s.need(proof['status']=='PASS' and proof['machine']=='aarch64' and proof['fish']=='fish, version 4.9.3' and set(cases)==names and
           all(r['exit']==0 for r in cases.values()) and all(cases[n]['activation']=='enabled' for n in enabled) and
           all(cases[n]['activation']=='yielded' and cases[n]['notifications']==0 for n in names-enabled-{'noninteractive'}) and
           cases['noninteractive']['notifications']==0 and value['case_inputs_preserved']==dict.fromkeys(names,True),
           'all eighteen exact real Done PTY cases and private inputs required')
    s.need(proof['scope']=='local notify-send process shim invocation only; no actual notification manager or visual display' and
           proof['wrapper_sha256']==receipt['files']['usr/share/cachy-asahi/fish-done/opt-in.fish']['sha256'] and
           proof['runtime_sha256']==receipt['files']['usr/share/cachy-asahi/fish-done/done.fish']['sha256'] and
           re.fullmatch('[0-9a-f]{64}',value['done_receipt_sha256']),'Done source/recorder receipt differs')
    def invocation(row,failed=False,kind='Foreground command',private=True):
        args=row['argv']
        s.need(len(args)==8 and args[:6]==['--hint=int:transient:1','--urgency='+('critical' if failed else 'normal'),
               '--icon=utilities-terminal','--app-name=fish','--expire-time=3000','--'] and
               args[6].startswith('Failed (' if failed else 'Done in ') and
               (not private or args[7]==kind+' completed.'),'exact private recorder invocation differs')
        return args
    foreground=cases['foreground']['proofs'];background=cases['background']['proofs']
    s.need(len(foreground)==2 and len(background)==3,'success/failure/watched/signal proof set differs')
    invocation(foreground[0]);s.need('Failed (7)' in invocation(foreground[1],True)[6],'foreground status lost')
    invocation(background[0],kind='Watched job')
    s.need('Failed (7)' in invocation(background[1],True,'Watched job')[6] and
           'Failed (143)' in invocation(background[2],True,'Watched job')[6],'watched status/signal lost')
    shown=cases['command-data']['proofs'];s.need(len(shown)==1 and
           '&lt;tag&gt; $HOME $(touch PWNED) --leading' in invocation(shown[0],private=False)[7],
           'opt-in literal/escaped command data differs')
    for name in ('transport-failure','transport-timeout'):
        rows=cases[name]['proofs'];s.need(len(rows)==1 and 0<=rows[0]['elapsed_seconds']<4.5,'transport deadline evidence missing')
        invocation(rows[0]['invocation'])
    s.need(cases['disable']['notifications']==0 and cases['repeat-preserve']['notifications']==1,'disable/repeat notification behavior differs')
    native=value['native_recorder_cases'];s.need(set(native)==names,'all eighteen native recorder copy/log joins required')
    for name,row in native.items():
        present=name!='notify-send';count=row['notification_count'];pids=row['recorded_pids']
        s.need(row['recorder_present'] is present and row['recorder_sha256']==(receipt['files'][s.RECORDER]['sha256'] if present else None) and
            type(count) is int and 0<=count<=32 and type(pids) is list and len(pids)==count and all(type(pid) is int and pid>0 for pid in pids) and
            type(row['fixture_notification_delta']) is int and row['fixture_notification_delta']==cases[name]['notifications'] and
            0<=row['fixture_notification_delta']<=count and (present or count==0) and
            re.fullmatch('[0-9a-f]{64}',row['notifications_sha256']),'native recorder byte/PID/count evidence differs')
    commands=value['commands'];s.need(len(commands)==1,'one complete adapted Done driver command required')
    row=commands[0]
    expected=['/usr/bin/python3','-I','-B','/fixtures/done-native.py','--source','/usr/share/cachy-asahi/fish-done','--output','/tmp/done16k/cases']
    s.need(row['argv']==expected and row['exit']==0 and row['group_absent'] is True and row['owned_processes_absent'] is True and
           0<=row['seconds']<=245 and 0<=row['stdout_bytes']+row['stderr_bytes']<=131072 and
           all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('stdout_sha256','stderr_sha256')),'exact Done command/result/group differs')
    return value


def capture_command(args,image,name,capture):
    return ['docker','run','--rm','--name',name,'--cidfile',str(args.private/'capture.cid'),'--pull=never','--platform=linux/arm64',
        '--label','org.cachy-asahi.done16k.job='+args.job_token,'--user',f'{os.getuid()}:{os.getgid()}',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=128','--memory=2g','--cpus=2',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--env','CACHY_DONE16K_CAPTURE=1','--env','PYTHONDONTWRITEBYTECODE=1',
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
                   row['Config']['Labels'].get('org.cachy-asahi.done16k.job')==args.job_token,'capture ownership differs')
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
    name='done16k-capture-'+args.job_token;started=False
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
            'etc/passwd':(stat.S_IFREG|0o644,b'root:x:0:0:private init:/tmp:/usr/bin/bash\nfixture:x:23001:23001:private tool fixture:/tmp/done16k/user:/usr/bin/bash\n'),
            'etc/group':(stat.S_IFREG|0o644,b'root:x:0:\nfixture:x:23001:\n'),
            'etc/nsswitch.conf':(stat.S_IFREG|0o644,b'passwd: files\ngroup: files\n'),
            'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')})
        ramfs=args.private/'initramfs.cpio';ramfs.write_bytes(generic.cpio(files))
        argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(copied),
              '-initrd',str(ramfs),'-append',generic.boot_arguments(True)+' fish_done16k=1',
              '-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot']
        report.update(qemu_argv=argv,tools={n:s.sha(s.read(p,64*1024**2)) for n,p in (('clang',Path(clang).resolve()),('ld.lld',Path(linker).resolve()),('qemu',Path(qemu).resolve()))},
                      initramfs_sha256=s.sha(s.read(ramfs,300*1024**2)),page_probe_sha256=s.sha(binary))
        code,uart,actor=supervise(argv,args.private/'uart.log',600);report['actors'].append(actor)
        diagnostic=failed_driver_diagnostic(uart,nonce,release,receipt)
        if diagnostic is not None:report['failed_driver_diagnostic']=diagnostic
        report.update(guest=guest_report(uart,code,nonce,release,receipt),natural_VM_exit=True,QEMU_exit=code,
                      uart=dict(bytes=len(uart),sha256=s.sha(uart)),status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT')
    except BaseException as error:
        report.update(status='FAIL',error_type=type(error).__name__,reason=str(error)[:256])
    finally:
        report['log_tails']={}
        try:
            build=args.private/'capture/recorder-build.json'
            if build.exists():report['recorder_build']=json.loads(s.read(build,262144))
            for filename in ('capture.log','compile.log','uart.log'):
                path=args.private/filename
                if path.exists():
                    data=s.read(path,1024**2);tail=data[-8192:]
                    report['log_tails'][filename]=dict(bytes=len(data),tail_sha256=s.sha(tail),tail_base64=base64.b64encode(tail).decode())
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
        s.need(report['guest']['status']==s.STATUS and report['guest']['test_transport']==s.test_transport(report['capture']),
               'final adapted transport/native compile joins required')
        work=args.kernel_work
        s.need(work==Path(os.environ['RUNNER_TEMP'])/'done16k-kernel' and work.is_absolute() and
               not any(p.is_symlink() for p in (work,*work.parents)) and work.stat().st_uid==os.getuid() and
               Path(report['kernel']['helper']['path'])==work/'helper/build_kernel.py' and
               report['kernel']['status']=='BUILT_ONLY' and report['kernel']['kernel_build']=='PASS',
               'completed owned kernel work required')
        shutil.rmtree(work);s.need(not work.exists(),'owned kernel work remains')
        report.update(status=s.STATUS,producer_cleanup=cleanup,kernel_work_removed=True)
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
