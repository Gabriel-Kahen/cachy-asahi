#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual UNBOUND management16K adapter; reuse held actor/kernel/ELF/cleanup APIs."""
import argparse,base64,json,os,re,secrets,shutil,signal,stat,sys,tarfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

CASES=['apps-inventory-install','apps-plan-install','apps-inventory-remove','apps-plan-remove','apps-list','apps-search','apps-show',
    'cache-plan','cache-verify','cache-concurrent-refusal','cache-apply','orphans-assess','orphans-plan','orphans-verify',
    *['orphans-refuse-'+n for n in ('sample-provider','sample-helper','linux-asahi','custom-important','sample-manual')]]

def apis(root):
    C.verify_source(root)
    module=C.load('management16k_held_tools_runner',root/'scripts/ci/tools-generic16k/run.py')
    module.s.check_source(root)
    return module

def inputs(args):
    binding=C.policy();C.verify_source(args.source_root);value=C.packet(args.packet)
    checks=C.load('management16k_archive_checks',args.source_root/'scripts/checks/package_checks.py')
    products,origins=C.package_payload(args.packet,value,checks)
    return binding,value,products

def payload(archive,receipt,generic,expected,base):
    C.need(receipt['status']=='CAPTURED_NATIVE_MANAGEMENT_PRIVATE_RUNTIME' and receipt['inventory_sha256']==base.s.LOCK and
        receipt['package_registration']==C.SCOPE and receipt['architecture']=='aarch64','capture scope/base differs')
    C.need(len(C.read(archive,270*1024**2))==receipt['archive']['bytes'] and C.sha(C.read(archive,270*1024**2))==receipt['archive']['sha256'],'capture archive differs')
    files={};total=0;elfs={}
    with tarfile.open(archive,'r:') as stream:
        for entry in stream:
            name=C.relative(entry.name);row=receipt['files'].get(name)
            C.need(name not in files and entry.isfile() and entry.uid==entry.gid==0 and len(files)<4096 and entry.size<=64*1024**2 and
                row and entry.size==row['bytes'] and entry.mode==row['mode'],'captured regular member differs')
            raw=stream.extractfile(entry).read();total+=len(raw);C.need(total<=256*1024**2 and C.sha(raw)==row['sha256'],'capture byte/hash bound')
            if raw.startswith(b'\x7fELF'):
                interpreter,needed=base.s.aligned(raw,generic);elfs[name]=dict(interpreter=interpreter,needed=needed)
            files[name]=(stat.S_IFREG|entry.mode,raw)
    C.need(set(files)==set(receipt['files']) and elfs==receipt['elf'],'complete actual ELF/file view required')
    for row in elfs.values():
        C.need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,'ELF interpreter absent')
        C.need(all(any(folder+n in files for folder in ('usr/lib/','lib/')) for n in row['needed']),'ELF dependency absent')
    required={'guest.py','signature_observer.py','original_guest.py','fixtures/catalog.tar','usr/lib/libalpm.so.16'}|{'usr/bin/'+n for n in C.TOOLS}|set(expected)
    C.need(required<=set(files),'complete management/runtime roots required')
    for name,(mode,data) in expected.items():C.need(files[name]==(stat.S_IFREG|mode,data),'actual native data payload differs')
    C.need(C.sha(files['fixtures/catalog.tar'][1])==receipt['fixture_archive_sha256'] and
        all(receipt['fixture_authority'][k] is True for k in ('synthetic','private_authority_removed','signing_processes_absent')) and
        receipt['fixture_authority']['production_trust']=='NOT_ESTABLISHED','isolated fresh TEST authority proof absent')
    C.need(files['guest.py'][1]==C.read(C.HERE/'guest.py') and files['signature_observer.py'][1]==C.read(C.HERE/'signature_observer.py'),'guest/diagnostic source differs')
    C.need(files['original_guest.py'][1]==C.read(base.s.HERE/'guest.py'),'unchanged guest API bytes differ')
    return files

def partial_commands(raw,nonce):
    records=[];failures=[]
    for line in raw.replace(b'\r',b'').splitlines():
        if not line.startswith((b'MANAGEMENT16K_COMMAND ',b'MANAGEMENT16K_COMMAND_FAILURE ')):continue
        label,token,data=line.split(b' ',2);C.need(token.decode()==nonce and len(line)<=200000,'bounded command diagnostic nonce/bytes')
        value=C.decode(data);row=value['command'];out=base64.b64decode(value['stdout_base64'],validate=True)
        C.need(len(out)==row['stdout_bytes'] and C.sha(out)==row['stdout_sha256'] and row['stdout_bytes']+row['stderr_bytes']<=131072,'raw command diagnostic hash bound')
        if label==b'MANAGEMENT16K_COMMAND_FAILURE':
            err=base64.b64decode(value['stderr_base64'],validate=True);C.need(not failures and len(err)==row['stderr_bytes'] and C.sha(err)==row['stderr_sha256'],'one bounded failed command diagnostic');failures.append(value)
        else:records.append(value)
    C.need([v['case'] for v in records]==CASES[:len(records)] and len(records)<=len(CASES) and
        (not failures or len(records)<len(CASES) and failures[0]['case']==CASES[len(records)]),'partial fixed command sequence differs')
    result=dict(acceptance_credit=False,commands=records,failed_commands=failures);observations=[]
    for line in raw.replace(b'\r',b'').splitlines():
        if not line.startswith((b'MANAGEMENT16K_SIGNATURE_FAILURE ',b'MANAGEMENT16K_SIGNATURE_UNAVAILABLE ')):continue
        label,token,data=line.split(b' ',2);C.need(token.decode()==nonce and len(line)<=66000 and not observations and len(failures)==1 and failures[0]['case']=='apps-plan-install','one bounded failure-only signature observation required')
        value=C.decode(data);C.need(value['acceptance_credit'] is False,'signature diagnostic cannot grant acceptance')
        if label==b'MANAGEMENT16K_SIGNATURE_FAILURE':
            observer=C.load('management16k_signature_observer',C.HERE/'signature_observer.py');observer.validate(value)
            C.need(value['original_command_sha256']==C.sha(json.dumps(failures[0]['command'],sort_keys=True,separators=(',',':')).encode()),'signature observation original command differs')
        observations.append(dict(label=label.decode(),value=value))
    if observations:result['signature_observations']=observations
    return result

def startup_seed(source,job_token,nonce,receipt):
    C.need(re.fullmatch('[0-9a-f]{40}',source) and re.fullmatch('[0-9a-f]{16}',job_token) and re.fullmatch('[0-9a-f]{32}',nonce),'startup clock source/job/nonce required')
    return dict(schema_version=1,purpose='MANAGEMENT16K_OBSERVED_RUNNER_UTC_STARTUP',source_commit=source,job_token=job_token,nonce=nonce,
        payload_manifest_sha256=C.sha(C.encoded(receipt)),host_realtime_ns=time.time_ns(),host_monotonic_ns=time.monotonic_ns())

def clock_report(value,nonce,receipt):
    seed=value['seed'];before=value['before'];after=value['after']
    C.need(set(seed)=={'schema_version','purpose','source_commit','job_token','nonce','payload_manifest_sha256','host_realtime_ns','host_monotonic_ns'} and type(seed['schema_version']) is int and len(C.encoded(seed))<=4096 and
        all(type(row[name]) is int and row[name]>=0 for row in (before,after) for name in ('realtime_ns','monotonic_ns')) and
        value['status']=='SET_VM_REALTIME_FROM_OBSERVED_RUNNER_UTC' and value['uid']==0 and value['authority']=='RECORDED_STARTUP_ANCHOR_NOT_CONTINUOUS_UTC_SYNCHRONIZATION' and
        value['seed_sha256']==C.sha(C.encoded(seed)) and seed['purpose']=='MANAGEMENT16K_OBSERVED_RUNNER_UTC_STARTUP' and seed['schema_version']==1 and
        seed['nonce']==nonce and seed['source_commit']==receipt['source_commit'] and seed['payload_manifest_sha256']==C.sha(C.encoded(receipt)) and
        all(type(seed[n]) is int and 0<seed[n]<2**63 for n in ('host_realtime_ns','host_monotonic_ns')) and re.fullmatch('[0-9a-f]{16}',seed['job_token']) and
        0<=after['monotonic_ns']-before['monotonic_ns']<=5*10**9 and seed['host_realtime_ns']<=after['realtime_ns']<=seed['host_realtime_ns']+after['monotonic_ns']-before['monotonic_ns']+10**9,'recorded real startup clock/source readback differs')
    return value

def guest_report(raw,code,nonce,release,receipt):
    C.need(code==0 and len(raw)<=1024**2 and not any(v in raw for v in (b'MANAGEMENT16K_ERROR',b'TOOLS16K FAIL',b'Kernel panic',b'Attempted to kill init')),'natural bounded guest exit0 required')
    lines=raw.replace(b'\r',b'').splitlines();markers=[f'UNAME16K aarch64 {release}'.encode(),b'GETCONF16K 16384',b'SMOKE16K: mmap,mprotect,file-offset PASS',f'TOOLS16K PASS {nonce}'.encode()]
    C.need(all(lines.count(v)==1 for v in markers) and [lines.index(v) for v in markers]==sorted(lines.index(v) for v in markers),'parsed exact16384 boot/page markers required')
    reports=[(n,v[len(b'MANAGEMENT16K_REPORT '):]) for n,v in enumerate(lines) if v.startswith(b'MANAGEMENT16K_REPORT ')]
    C.need(len(reports)==1 and lines.index(markers[2])<reports[0][0]<lines.index(markers[3]) and len(reports[0][1])<=65536,'one ordered bounded report required')
    result=C.decode(reports[0][1]);C.need(result['status']==C.STATUS and result['nonce']==nonce and result['kernel']==release and
        result['architecture']=='aarch64' and result['page_size']==16384 and result['uid']==result['gid']==23001 and result['groups']==[] and result['NNP'] is True and result['capabilities_zero'] is True and
        result['package_registration']==C.SCOPE and result['payload_manifest_sha256']==C.sha(C.encoded(receipt)) and
        result['fixture_archive_sha256']==receipt['fixture_archive_sha256'] and result['GUI']==result['hardware']=='NOT_RUN' and result['release_admission'] is False and
        all(result[k] is True for k in ('payload_preserved','user_config_preserved','owned_processes_absent','private_fixtures_removed')),'ordinary guest/preservation/scope differs')
    clock_report(result['clock_setup'],nonce,receipt)
    rows=[]
    for index,line in enumerate(lines):
        if not line.startswith(b'MANAGEMENT16K_COMMAND '):continue
        C.need(lines.index(markers[2])<index<reports[0][0] and len(line)<=200000,'raw command ordering/byte bound')
        _,token,data=line.split(b' ',2);C.need(token.decode()==nonce,'raw command nonce differs');row=C.decode(data);out=base64.b64decode(row['stdout_base64'],validate=True);command=row['command']
        C.need(row['case']==command['case'] and len(out)==command['stdout_bytes'] and C.sha(out)==command['stdout_sha256'] and
            command['stdout_bytes']+command['stderr_bytes']<=131072 and command['group_absent'] is True and command['owned_processes_absent'] is True and
            0<=command['seconds']<=35 and command['exit']==(1 if command['case']=='cache-concurrent-refusal' or command['case'].startswith('orphans-refuse-') else 0) and
            command['argv'][0] in ('/usr/bin/cachy-asahi-apps','/usr/bin/cachy-asahi-cache','/usr/bin/cachy-asahi-orphans') and '--repository-source' not in command['argv'],'actual installed-path command proof differs')
        rows.append(row)
    C.need([r['case'] for r in rows]==CASES and result['commands']==[r['command'] for r in rows],'complete exact command/raw-output set required')
    apps=result['results']['apps'];cache=result['results']['cache'];orphan=result['results']['orphans']
    C.need(apps['default_prefix'] is True and apps['repository_override'] is False and apps['Git_checkout'] is False and apps['signer']==receipt['fixture_authority']['signer'] and
        [r['operation'] for r in apps['observed_plans']]==['install','remove'] and all(r['not_applied'] is True and r['db_preserved'] is True for r in apps['observed_plans']),'signed collected Apps plan/default helpers differ')
    C.need(all(C.sha(C.encoded(row['inventory']))==row['inventory_sha256'] and row['inventory']['observation']['payload_verified'] is False and row['inventory']['observation']['hardware_verified'] is False
        for row in apps['observed_plans']),'complete observed inventory/raw stdout hash join differs')
    C.need(cache['real_ALPM_version'].startswith('16.') and cache['concurrent_refusal'] is True and cache['protected_unselected_database_preserved'] is True and cache['lock_released'] is True and
        cache['removed_objects']==['selected-1-1-any.pkg.tar.xz','selected-1-1-any.pkg.tar.xz.sig'] and cache['disk_space']=='NOT_MEASURED','actual Cache cleanup/exclusion differs')
    C.need(orphan['libalpm'].startswith('16.') and orphan['required_provided_optional_protected'] is True and orphan['not_applied'] is True and orphan['database_preserved'] is True and
        orphan['explicit_selected']==['sample-leaf','sample-oldprovider'],'actual readonly Orphan cases differ')
    C.need(cache['journal']['phase']=='APPLIED' and cache['journal']['lock_release']=='OWN_LOCK_RELEASED' and cache['journal']['alpm']['version']==cache['real_ALPM_version'] and
        orphan['assessment']['scope']=='LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF' and orphan['assessment']['apply_supported'] is False and
        orphan['plan']['status']=='NOT_APPLIED' and orphan['plan']['apply_supported'] is False,'bounded raw fixture journal/assessment/plan differs')
    return result,rows

def capture_command(args,base,image,name,capture):
    argv=base.capture_command(args,image,name,capture);old='type=bind,src='+str(base.s.HERE)+',dst=/source,readonly'
    C.need(argv.count(old)==1,'held capture source mount shape differs');argv[argv.index(old)]='type=bind,src='+str(C.HERE)+',dst=/source,readonly'
    pos=argv.index('--entrypoint=/usr/bin/python3');argv[pos:pos]=['--mount','type=bind,src='+str(args.packet)+',dst=/inputs,readonly'];return argv

def trial(args):
    binding,packet,expected=inputs(args);base=apis(args.source_root)
    if not args.execute:return dict(status='BOUND_INPUTS_VERIFIED_NOT_EXECUTED',scope=C.SCOPE)
    image,owner=base.preflight(args)
    for path in (args.private,args.output):
        C.safe(path);C.need(not path.exists() and not any(path.is_relative_to(p) or p.is_relative_to(path) for p in (args.source_root,args.base_dir,args.packet)),'fresh separate work required')
    C.need(not args.private.is_relative_to(args.output) and not args.output.is_relative_to(args.private),'private/public separation required')
    os.umask(0o077);args.private.mkdir(mode=0o700);args.output.mkdir(mode=0o700)
    report=dict(status='FAIL',scope=C.SCOPE,source_commit=args.source_commit,job_token=args.job_token,image_id=image,native_packet_sha256=binding['packet_index']['sha256'],
        GUI='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',release_admission=False,producer_cleanup='PENDING',actors=[],consumer_cleanup={'capture_absent':False,'private_removed':False})
    base.s.save(args.output/'runtime.json',report);name='management16k-capture-'+args.job_token;started=False
    try:
        C.need(not base.query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'fresh capture name required')
        capture=args.private/'capture';capture.mkdir(mode=0o700);started=True
        code,_,actor=base.supervise(capture_command(args,base,image,name,capture),args.private/'capture.log',240);report['actors'].append(actor);C.need(code==0,'native readonly runtime capture failed')
        raw=C.read(capture/'capture.json',1024**2);receipt=C.decode(raw)
        C.need(receipt['image_id']==image and receipt['source_commit']==args.source_commit and receipt['native_inputs']==packet['packages'] and receipt['packet_sha256']==binding['packet_index']['sha256'],'capture image/source/native-packet joins differ')
        generic=base.s.load(args.source_root,'scripts/virtual/generic16k/fixture.py');files=payload(capture/'payload.tar',receipt,generic,expected,base);report['capture']=receipt
        kernel=C.decode(C.read(args.kernel_receipt,65536));image_path=base.kernel(kernel,args.source_root);report['kernel']=kernel;config=C.read(Path(kernel['config']['path']),65536).decode()
        copied=args.private/'Image';shutil.copyfile(image_path,copied);C.need(C.sha(C.read(copied,256*1024**2))==kernel['image']['sha256'],'copied kernel differs')
        clang=shutil.which('clang');linker=shutil.which('ld.lld');qemu=shutil.which('qemu-system-aarch64');C.need(clang and linker and qemu,'accepted fixture tools required')
        smoke=args.private/'smoke';argv=[clang,'--target=aarch64-linux-gnu','-nostdlib','-static','-fuse-ld='+linker,'-O2','-fno-stack-protector','-fno-builtin','-Wl,-z,max-page-size=16384','-Wl,-e,_start',str(args.source_root/'scripts/virtual/generic16k/smoke.c'),'-o',str(smoke)]
        code,_,actor=base.supervise(argv,args.private/'compile.log',60);report['actors'].append(actor);C.need(code==0,'unchanged page probe build failed')
        binary=C.read(smoke);base.s.aligned(binary,generic);nonce=secrets.token_hex(16);release=kernel['kernel_release']
        clock_seed=startup_seed(args.source_commit,args.job_token,nonce,receipt);clock_raw=C.encoded(clock_seed)
        files.update({'init':(stat.S_IFREG|0o755,base.init(nonce,release)),'smoke':(stat.S_IFREG|0o755,binary),'payload.json':(stat.S_IFREG|0o644,raw),'clock-seed.json':(stat.S_IFREG|0o444,clock_raw),
            'page-data':(stat.S_IFREG|0o444,b'A'*16384+b'B'*16384),'etc/passwd':(stat.S_IFREG|0o644,b'root:x:0:0:private init:/tmp:/usr/bin/bash\nfixture:x:23001:23001:private fixture:/tmp/management16k/home:/usr/bin/bash\n'),
            'etc/group':(stat.S_IFREG|0o644,b'root:x:0:\nfixture:x:23001:\n'),'etc/nsswitch.conf':(stat.S_IFREG|0o644,b'passwd: files\ngroup: files\n'),
            'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')})
        ramfs=args.private/'initramfs.cpio';ramfs.write_bytes(generic.cpio(files));C.need(ramfs.stat().st_size<=300*1024**2,'initramfs original byte bound')
        report.update(boot_inputs=dict(nonce=nonce,init_sha256=C.sha(files['init'][1]),payload_manifest_sha256=C.sha(raw),initramfs_sha256=C.sha(C.read(ramfs,300*1024**2)),clock_seed=clock_seed,clock_seed_sha256=C.sha(clock_raw)),page_probe_sha256=C.sha(binary))
        argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(copied),'-initrd',str(ramfs),'-append',generic.boot_arguments(True)+' tools16k=1 management16k=1','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot','-qmp','unix:'+str(args.private/'qmp.sock')+',server=on,wait=off']
        report['qemu_argv']=argv;report['tools']={n:C.sha(base.s.read(Path(p).resolve(),64*1024**2)) for n,p in [('clang',clang),('ld.lld',linker),('qemu',qemu)]};report['vm_observation']={}
        diagnostic=(report['vm_observation'],lambda child,output,deadline:base.vm_observation(child,args.private/'qmp.sock',kernel,config,output,nonce,deadline))
        report['clock_dispatch']=dict(host_realtime_ns=time.time_ns(),host_monotonic_ns=time.monotonic_ns())
        C.need(0<=report['clock_dispatch']['host_monotonic_ns']-clock_seed['host_monotonic_ns']<=30*10**9 and
            0<=report['clock_dispatch']['host_realtime_ns']-clock_seed['host_realtime_ns']<=31*10**9,'startup clock seed stale or host clock moved backwards before VM dispatch')
        code,uart,actor=base.supervise(argv,args.private/'uart.log',900,diagnostic=diagnostic);report['actors'].append(actor)
        guest,commands=guest_report(uart,code,nonce,release,receipt)
        C.need(guest['clock_setup']['seed']==clock_seed and guest['clock_setup']['seed_sha256']==report['boot_inputs']['clock_seed_sha256'],'guest clock differs from original host-observed boot seed')
        report.update(guest=guest,raw_commands=commands,natural_VM_exit=True,QEMU_exit=code,status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT')
        inputs(args) # Exact external packet/source preservation, not a new acceptance receipt.
    except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,reason=str(error)[:256])
    finally:
        report['log_tails']={}
        try:
            for name_log in ('capture.log','compile.log','uart.log'):
                path=args.private/name_log
                if path.exists():
                    data=C.read(path,1024**2);tail=data[-8192:];report['log_tails'][name_log]=dict(bytes=len(data),sha256=C.sha(data),tail_base64=base64.b64encode(tail).decode())
                    if name_log=='uart.log' and 'raw_commands' not in report and 'boot_inputs' in report:
                        report['partial_command_observations']=partial_commands(data,report['boot_inputs']['nonce'])
        except BaseException as error:report.update(status='FAIL',log_export_error=type(error).__name__)
        old=signal.getsignal(signal.SIGALRM)
        def expired(*_):raise TimeoutError('owned consumer cleanup deadline')
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,90)
        try:
            report['consumer_cleanup']=base.retire(args,name,image,started);C.need(owner.inspect_image(image,args.job_token)['Id']==image,'borrowed producer changed')
        except BaseException as error:report.update(status='FAIL',cleanup_error=type(error).__name__)
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
        base.s.save(args.output/'runtime.json',report)
    return report

def producer_ready(output):
    path=output/'runtime.json'
    if not path.exists():return True # No trial actor starts before this receipt is published.
    value=C.decode(C.read(path,2*1024**2));cleanup=value.get('consumer_cleanup',{})
    C.need(cleanup.get('capture_absent') is True and cleanup.get('private_removed') is True,'consumer retirement unknown; retain producer')
    return True

def finalize(args):
    base=apis(args.source_root);report=C.decode(C.read(args.output/'runtime.json',2*1024**2));producer=C.decode(C.read(args.base_dir/'report.json'))
    try:
        producer_ready(args.output);cleanup=producer['owned_cleanup']
        C.need(report['status']=='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT' and report['job_token']==args.job_token==producer['ownership']['token'] and
            report['natural_VM_exit'] is True and report['QEMU_exit']==0 and len(report['actors'])==3 and all(r['exit']==0 and r['natural_exit'] is True and r['group_absent'] is True for r in report['actors']) and
            cleanup['status']=='PASS' and cleanup['probe']['absence_verified'] is True and cleanup['image']['absence_verified'] is True and cleanup['image']['id']==report['image_id'],'ordered consumer/producer cleanup absent')
        work=C.safe(args.kernel_work);C.need(work==Path(os.environ['RUNNER_TEMP'])/'tools16k-kernel' and work.stat().st_uid==os.getuid() and
            Path(report['kernel']['helper']['path'])==work/'helper/build_kernel.py' and report['kernel']['kernel_build']=='PASS','completed exact owned kernel work required')
        shutil.rmtree(work);C.need(not work.exists(),'completed kernel work remains');report.update(status=C.STATUS,producer_cleanup=cleanup,kernel_work_removed=True)
    except BaseException as error:report.update(status='FAIL',finalize_error=type(error).__name__)
    base.s.save(args.output/'runtime.json',report);return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=['check','trial','producer-ready','finalize'])
    for name in ('source-root','packet','base-dir','private','output','kernel-receipt','kernel-work'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--source-commit');parser.add_argument('--job-token');parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    C.policy() # Source-only UNBOUND refusal before every external actor/secret.
    def interrupted(*_):raise KeyboardInterrupt('owned management16K controller interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    if args.mode=='check':inputs(args);value=dict(status='BOUND_INPUTS_VERIFIED_NOT_EXECUTED')
    elif args.mode=='producer-ready':producer_ready(args.output);value=dict(status='CONSUMERS_RETIRED_OR_NOT_STARTED')
    else:value=trial(args) if args.mode=='trial' else finalize(args)
    print(json.dumps(dict(status=value['status'],scope=C.SCOPE)));raise SystemExit(value['status']=='FAIL')
