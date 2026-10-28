#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual owned574 capture + diskless 16 KiB CLI trial. No product rebuild."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import support as s


def query(argv):
    row=subprocess.run(list(map(str,argv)),capture_output=True,timeout=25)
    s.need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=65536,'bounded local query failed')
    return row.stdout.decode().strip()


def preflight(args):
    s.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
           os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64','explicit disposable native CI required')
    s.need(not any(k.startswith('DOCKER_') for k in os.environ),'local default Docker only')
    s.need(s.HERE==args.source_root/'scripts/ci/welcome-doctor-generic16k','adopted source location required')
    s.need(re.fullmatch('[0-9a-f]{40}',args.source_commit) and re.fullmatch('[0-9a-f]{16}',args.job_token),'source/job identity required')
    s.need(query(['git','-C',args.source_root,'rev-parse','HEAD'])==args.source_commit and
           query(['git','-C',args.assets,'rev-parse','HEAD'])==s.INPUT_SOURCE,'immutable checkouts differ')
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
           receipt['product_input_source']==s.INPUT_SOURCE and receipt['index_sha256']==s.INDEX and
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
    required={'guest.py',*[ 'usr/bin/'+name for name in ('bash','env','uname','getconf','mount','python3','cachy-asahi-welcome','cachy-asahi-doctor')]}
    required.update(name for product in receipt['products'].values() for name in product['payload'])
    s.need(required<=set(files) and elf_names==set(receipt['elf']),'complete product/tool ELF roots required')
    for row in receipt['elf'].values():
        s.need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,'closed interpreter absent')
        s.need(all(any(folder+lib in files for folder in ('usr/lib/','lib/')) for lib in row['needed']),'DT_NEEDED closure absent')
    return files


def kernel(receipt,root):
    s.need(receipt['status']=='BUILT_ONLY' and receipt['kernel_build']=='PASS' and receipt['boot_diagnostics'] is True and
           receipt['image_check']['header_page_size']==16384 and receipt['module_policy']['CONFIG_MODULES']=='n' and
           receipt['archive']['sha256']=='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad' and
           receipt['source_commit']=='94fb23346d522edf53722357c426a3e58030beea' and
           receipt['helper']['sha256']==s.pins()['files']['scripts/virtual/generic16k/build_kernel.py']['sha256'],
           'accepted diagnostic16K kernel receipt required')
    image=Path(receipt['image']['path']);config=Path(receipt['config']['path'])
    s.need(image.stat().st_size==receipt['image']['bytes']<=256*1024**2 and
           s.sha(s.read(image,256*1024**2))==receipt['image']['sha256'] and
           s.sha(s.read(config,65536))==receipt['config']['sha256'],'kernel Image/config identity differs')
    helper=s.load(root,'scripts/virtual/generic16k/build_kernel.py')
    helper.config_check(config,True);helper.image_check(image);return image


def init(nonce,release):
    s.need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}',release),'guest marker identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C PYTHONDONTWRITEBYTECODE=1
fail() {{ printf 'WELCOME16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc || fail
machine=$(/usr/bin/uname -m) || fail
release=$(/usr/bin/uname -r) || fail
page=$(/usr/bin/getconf PAGESIZE) || fail
printf 'UNAME16K %s %s\\nGETCONF16K %s\\n' "$machine" "$release" "$page"
[[ "$machine" == aarch64 && "$release" == '{release}' && "$page" == 16384 ]] || fail
/smoke || fail
/usr/bin/python3 -I -B /guest.py '{nonce}' '{release}' || fail
printf 'WELCOME16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def guest_report(output,code,nonce,release,receipt):
    s.need(code==0 and len(output)<=1024**2 and not any(message in output for message in
           (b'WELCOME16K FAIL',b'WELCOME16K_ERROR',b'Kernel panic',b'Attempted to kill init')),
           'natural bounded guest exit0 required')
    lines=output.replace(b'\r',b'').splitlines();markers=[f'UNAME16K aarch64 {release}'.encode(),b'GETCONF16K 16384',
        b'SMOKE16K: mmap,mprotect,file-offset PASS',f'WELCOME16K PASS {nonce}'.encode()]
    s.need(all(lines.count(x)==1 for x in markers),'exact actual16K markers required')
    positions=[lines.index(x) for x in markers];s.need(positions==sorted(positions),'marker ordering differs')
    reports=[(i,line.removeprefix(b'WELCOME16K_REPORT ')) for i,line in enumerate(lines) if line.startswith(b'WELCOME16K_REPORT ')]
    s.need(len(reports)==1 and positions[2]<reports[0][0]<positions[3] and len(reports[0][1])<=65536,'one bounded guest report required')
    value=json.loads(reports[0][1])
    s.need(value['status']=='PASS_GENERIC_16K_WELCOME_DOCTOR_CLI_ONLY' and value['nonce']==nonce and
           value['architecture']=='aarch64' and value['page_size']==16384 and value['kernel']==release and
           value['private_report_mode']=='0600' and value['no_overwrite']==value['symlink_refusal']=='PASS' and
           value['config_preserved'] is True and value['payload_preserved'] is True and
           value['package_registration']=='NOT_INSTALLED_EXACT_PAYLOADS_UNPACKED_ONLY' and
           value['GUI']==value['hardware']==value['performance']=='NOT_RUN' and value['release_admission'] is False,
           'guest behavior/limits differ')
    status=value['welcome_status'];platform=value['doctor_platform']
    s.need(status['architecture']=='aarch64' and status['page_size']==16384 and status['kernel']==release and
           status['hardware_compatibility']=='not-assessed' and status['welcome_version']=='0.1.0' and
           status['package_database']=='unavailable' and
           platform==dict(architecture='aarch64',page_size_bytes=16384,kernel=release) and
           value['doctor_scope']=='local observations only' and
           value['payload_manifest_sha256']==s.sha((json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode()),
           'actual CLI platform/closure report differs')
    commands=value['commands'];s.need(len(commands)==13 and all(c['group_absent'] is True and c['seconds']<=35 for c in commands),'finite13 command set required')
    expected=[['cachy-asahi-welcome','--help'],['cachy-asahi-welcome','--version'],['cachy-asahi-welcome','--status'],
              ['cachy-asahi-welcome','--status','--json'],*[['cachy-asahi-welcome','--guide',n] for n in ('first-run','updates','recovery')],
              ['cachy-asahi-welcome','--guide','../../etc/shadow'],['cachy-asahi-doctor','--help'],['cachy-asahi-doctor','--json'],
              ['cachy-asahi-doctor','--json','--output','/tmp/welcome16k/reports/report.json'],
              ['cachy-asahi-doctor','--output','/tmp/welcome16k/reports/report.json'],['cachy-asahi-doctor','--output','/tmp/welcome16k/reports/alias']]
    for n,(row,args) in enumerate(zip(commands,expected)):
        s.need(row['argv']==['/usr/bin/'+args[0],*args[1:]] and row['exit']==(2 if n in (7,11,12) else 0) and
               0<=row['stdout_bytes']+row['stderr_bytes']<=131072 and
               all(re.fullmatch('[0-9a-f]{64}',row[k]) for k in ('stdout_sha256','stderr_sha256')),'exact command/result differs')
    expected_guides={n:receipt['files']['usr/share/doc/cachy-asahi-welcome/'+n+'.txt']['sha256'] for n in ('first-run','updates','recovery')}
    s.need(value['guide_sha256']==expected_guides and all(commands[i]['stdout_sha256']==expected_guides[n]
           for i,n in enumerate(('first-run','updates','recovery'),4)),'actual guide/product hash join differs');return value


def capture_command(args,image,name,capture):
    return ['docker','run','--rm','--name',name,'--cidfile',str(args.private/'capture.cid'),'--pull=never','--platform=linux/arm64',
        '--label','org.cachy-asahi.welcome16k.job='+args.job_token,'--user',f'{os.getuid()}:{os.getgid()}',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=128','--memory=2g','--cpus=2',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--env','CACHY_WELCOME16K_CAPTURE=1','--env','PYTHONDONTWRITEBYTECODE=1',
        '--mount','type=bind,src='+str(s.HERE)+',dst=/source,readonly',
        '--mount','type=bind,src='+str(args.source_root)+',dst=/repo,readonly',
        '--mount','type=bind,src='+str(args.assets)+',dst=/assets,readonly',
        '--mount','type=bind,src='+str(args.base_dir/'installed-packages.lock')+',dst=/expected.lock,readonly',
        '--mount','type=bind,src='+str(capture)+',dst=/out','--entrypoint=/usr/bin/python3',image,'-I','-B','/source/capture.py','--image-id',image]


def retire(args,name,image,started):
    result=dict(capture_absent=not started,private_removed=False,producer='BORROWED_PRESERVED')
    if started:
        cid=s.read(args.private/'capture.cid',128).decode().strip();s.need(re.fullmatch('[0-9a-f]{64}',cid),'capture CID required')
        found=query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'])
        s.need(found in ('',name),'capture name ambiguous')
        if found:
            rows=json.loads(query(['docker','container','inspect',cid]));s.need(len(rows)==1,'one owned capture required');row=rows[0]
            s.need(row['Id']==cid and row['Name']=='/'+name and row['Image']==image and
                   row['Config']['Labels'].get('org.cachy-asahi.welcome16k.job')==args.job_token,'capture ownership differs')
            query(['docker','rm','-f',cid])
        s.need(not query(['docker','container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}']) and
               not query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'capture still present')
        result['capture_absent']=True
    shutil.rmtree(args.private);result['private_removed']=not args.private.exists();return result


def trial(args):
    s.check_source(args.source_root);products=s.products(args.source_root,args.assets)
    if not args.execute:return dict(status='SOURCE_INPUTS_VERIFIED_NOT_EXECUTED',products=products)
    image,owner=preflight(args)
    for path in (args.private,args.output):
        s.need(path.is_absolute() and not path.exists() and not any(p.is_symlink() for p in (path,*path.parents)) and
               not any(path.is_relative_to(p) or p.is_relative_to(path) for p in (args.source_root,args.assets,args.base_dir)),
               'fresh separate ordinary work required')
    s.need(not args.private.is_relative_to(args.output) and not args.output.is_relative_to(args.private),'private/public separation required')
    os.umask(0o077);args.private.mkdir(mode=0o700);args.output.mkdir(mode=0o700)
    generic=s.load(args.source_root,'scripts/virtual/generic16k/fixture.py')
    report=dict(status='FAIL',scope=s.SCOPE,source_commit=args.source_commit,job_token=args.job_token,image_id=image,
        product_input_source=s.INPUT_SOURCE,index_sha256=s.INDEX,products=products,GUI='NOT_RUN',hardware='NOT_RUN',
        performance='NOT_RUN',release_admission=False,producer_cleanup='PENDING')
    name='welcome16k-capture-'+args.job_token;started=False
    try:
        s.need(not query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'fresh capture name required')
        capture=args.private/'capture';capture.mkdir(mode=0o700);started=True
        code,_=generic.supervise(capture_command(args,image,name,capture),args.private/'capture.log',240,1024**2)
        s.need(code==0,'native byte capture failed');raw=s.read(capture/'capture.json');receipt=json.loads(raw)
        s.need(receipt['image_id']==image and receipt['products']==products,'capture product/image join differs')
        report['capture']=receipt;files=payload(capture/'payload.tar',receipt,generic)
        kr=json.loads(s.read(args.kernel_receipt,65536));image_path=kernel(kr,args.source_root)
        report['kernel']=kr;report['kernel_config']=s.read(Path(kr['config']['path']),65536).decode()
        copied=args.private/'Image';shutil.copyfile(image_path,copied);s.need(s.sha(s.read(copied,256*1024**2))==kr['image']['sha256'],'copied Image differs')
        smoke=args.private/'smoke';clang=shutil.which('clang');linker=shutil.which('ld.lld');qemu=shutil.which('qemu-system-aarch64')
        s.need(clang and linker and qemu,'accepted fixture tools required')
        smoke_source=args.source_root/'scripts/virtual/generic16k/smoke.c'
        argv=[clang,'--target=aarch64-linux-gnu','-nostdlib','-static','-fuse-ld='+linker,'-O2','-fno-stack-protector','-fno-builtin',
              '-Wl,-z,max-page-size=16384','-Wl,-e,_start',str(smoke_source),'-o',str(smoke)]
        code,_=generic.supervise(argv,args.private/'compile.log',60);s.need(code==0,'unchanged page probe build failed')
        binary=s.read(smoke);s.aligned(binary,generic);nonce=secrets.token_hex(16);release=kr['kernel_release']
        files.update({'init':(stat.S_IFREG|0o755,init(nonce,release)),'smoke':(stat.S_IFREG|0o755,binary),
            'payload.json':(stat.S_IFREG|0o644,raw),'page-data':(stat.S_IFREG|0o444,b'A'*16384+b'B'*16384),
            'proc':(stat.S_IFDIR|0o555,b''),'tmp':(stat.S_IFDIR|0o700,b'')})
        ramfs=args.private/'initramfs.cpio';ramfs.write_bytes(generic.cpio(files))
        argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(copied),
              '-initrd',str(ramfs),'-append',generic.boot_arguments(True)+' welcome_doctor16k=1',
              '-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot']
        report.update(qemu_argv=argv,tools={n:s.sha(s.read(p,64*1024**2)) for n,p in (('clang',Path(clang).resolve()),('ld.lld',Path(linker).resolve()),('qemu',Path(qemu).resolve()))},
                      initramfs_sha256=s.sha(s.read(ramfs,300*1024**2)),page_probe_sha256=s.sha(binary))
        code,uart=generic.supervise(argv,args.private/'uart.log',600,1024**2)
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
               report['QEMU_exit']==0 and consumer['capture_absent'] is True and consumer['private_removed'] is True and
               consumer['producer']=='BORROWED_PRESERVED' and cleanup['status']=='PASS' and
               cleanup['probe']['absence_verified'] is True and cleanup['image']['absence_verified'] is True and
               cleanup['image']['id']==report['image_id'],'ordered consumer/producer cleanup required')
        work=args.kernel_work
        s.need(work==Path(os.environ['RUNNER_TEMP'])/'welcome16k-kernel' and work.is_absolute() and
               not any(p.is_symlink() for p in (work,*work.parents)) and work.stat().st_uid==os.getuid() and
               Path(report['kernel']['helper']['path'])==work/'helper/build_kernel.py' and
               report['kernel']['status']=='BUILT_ONLY' and report['kernel']['kernel_build']=='PASS',
               'completed owned kernel work required')
        shutil.rmtree(work);s.need(not work.exists(),'owned kernel work remains')
        report.update(status='PASS_GENERIC_16K_WELCOME_DOCTOR_CLI_ONLY',producer_cleanup=cleanup,kernel_work_removed=True)
    except BaseException as error:report.update(status='FAIL',finalize_error=type(error).__name__)
    s.save(args.output/'runtime.json',report);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('trial','finalize'))
    for name in ('base-dir','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--job-token',required=True)
    for name in ('source-root','assets','private','kernel-receipt','kernel-work'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--source-commit');parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    def interrupted(*_):raise KeyboardInterrupt('owned16K controller interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    value=trial(args) if args.mode=='trial' else finalize(args)
    print(json.dumps(dict(status=value['status'],scope=s.SCOPE)))
    raise SystemExit(value['status']=='FAIL')
