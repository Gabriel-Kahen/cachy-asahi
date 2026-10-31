#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two finite consumers: compile-only574 capture, then private-loader16K VM."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import sys
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c


def init(nonce,release):
    c.need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[A-Za-z0-9_.+-]{1,128}',release),'fixed guest identity')
    return f'''#!/usr/bin/bash
export PATH=/usr/bin:/bin HOME=/tmp LC_ALL=C LANG=C PYTHONDONTWRITEBYTECODE=1
fail() {{ printf 'GLIBC16K FAIL {nonce}\\n'; exec /smoke poweroff; }}
/usr/bin/mount -t proc -o nosuid,nodev,noexec proc /proc || fail
/usr/bin/mount -t devtmpfs -o nosuid devtmpfs /dev || fail
/usr/bin/mkdir -m 0755 /dev/pts || fail
/usr/bin/mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts /dev/pts || fail
/usr/bin/rm -f /dev/ptmx || fail
/usr/bin/ln -s pts/ptmx /dev/ptmx || fail
/usr/bin/ln -s /proc/self/fd /dev/fd || fail
[[ $(/usr/bin/uname -m) == aarch64 && $(/usr/bin/uname -r) == '{release}' && $(/usr/bin/getconf PAGESIZE) == 16384 ]] || fail
printf 'GLIBC16K BOOT {nonce} 16384\\n'
/smoke || fail
/usr/bin/python3 -I -B /guest.py '{nonce}' '{release}' || fail
printf 'GLIBC16K PASS {nonce}\\n'
exec /smoke poweroff
'''.encode()


def payload(archive,receipt,stage_rows,generic,root):
    c.need(receipt['status']=='CAPTURED_GLIBC_CLIENTS_NOT_EXECUTED' and receipt['inventory_sha256']==c.LOCK and
           receipt['pair_sha256']==c.PACKAGE_SHA and receipt['archive']==dict(bytes=archive.stat().st_size,
           sha256=c.sha(c.read(archive,270*1024**2))),'capture identity differs')
    c.compile_receipt(receipt['compile']);files={};total=0;elfs={}
    with tarfile.open(archive,'r:') as stream:
        for entry in stream:
            name=c.relative(entry.name);c.need(entry.isfile() and entry.uid==entry.gid==0 and name not in files and
                len(files)<4096 and entry.size<=64*1024**2,'bounded ordinary payload members only')
            row=receipt['files'][name];raw=stream.extractfile(entry).read();total+=len(raw)
            c.need(total<=256*1024**2 and entry.size==len(raw)==row['bytes'] and entry.mode==row['mode'] and c.sha(raw)==row['sha256'],
                   'captured payload bytes/mode differ')
            if raw.startswith(b'\x7fELF'):elfs[name]=dict(c.aligned(raw,generic),scope='candidate' if name.startswith(c.PREFIX+'/') or name.startswith('work/clients/') else 'bootstrap')
            files[name]=(stat.S_IFREG|entry.mode,raw)
    c.need(set(files)==set(receipt['files']) and elfs==receipt['elf'],'closed captured file/ELF set required')
    candidate={name[len(c.PREFIX)+1:]:row for name,row in receipt['files'].items() if name.startswith(c.PREFIX+'/')}
    c.need({n:{k:r[k] for k in ('bytes','mode','sha256')} for n,r in candidate.items()}==stage_rows,'actual accepted candidate stage differs')
    for name in ('runner.py','abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c'):
        data=files['runtime/'+name][1];expected=c.dependencies()['scripts/ci/glibc-owned-runtime/'+name]
        c.need(len(data)==expected['bytes'] and c.sha(data)==expected['sha256'],'unchanged accepted driver source differs')
    c.need(files['guest.py'][1]==c.read(c.HERE/'guest.py') and c.decode(files['runtime-inputs.json'][1])==c.spec() and
           c.decode(files['compile.json'][1])==receipt['compile'],'wrapper/private role/native receipt join differs')
    for name in c.CLIENTS:
        raw=files['work/clients/'+name][1];expected=receipt['compile']['compiled_files'][name]
        c.need(len(raw)==expected['bytes'] and c.sha(raw)==expected['sha256'] and expected['elf_machine']==183,'client compile/capture join differs')
    c.elf_closure(elfs,files)
    c.need({'smoke','usr/bin/python3',*['usr/bin/'+name for name in c.TOOLS]}<=set(files),'bootstrap/probe closure roots absent')
    return files


def guest_report(uart,code,nonce,release,capture):
    c.need(code==0 and len(uart)<=1024**2 and b'SMOKE16K: mmap,mprotect,file-offset PASS' in uart,'natural VM/page probe required')
    lines=[line.rstrip(b'\r') for line in uart.splitlines() if line.startswith(b'GLIBC16K ')]
    c.need(len(lines)==3 and lines[0]==('GLIBC16K BOOT '+nonce+' 16384').encode() and
           lines[2]==('GLIBC16K PASS '+nonce).encode(),'nonce-bound ordered16K protocol required')
    prefix=('GLIBC16K REPORT '+nonce+' ').encode();c.need(lines[1].startswith(prefix),'one attributable runtime report')
    raw=base64.b64decode(lines[1][len(prefix):],validate=True);c.need(len(raw)<=512*1024,'guest report cap')
    value=c.decode(raw);c.guest_receipt(value)
    c.need(value['kernel']==release and value['commands'][:13]==capture['compile']['commands'] and
           value['compiled_files']==capture['compile']['compiled_files'],'kernel/compile-once command lineage differs')
    for name,row in value['runtime_files'].items():
        key=name.removeprefix('/');expected=capture['files'].get(key)
        c.need(expected and row['sha256']==expected['sha256'] and row['bytes']==expected['bytes'],'guest mapped an uncaptured file')
    return value


def capture_command(args,image,name,folder,stage):
    command=['docker','run','--name',name,'--cidfile',str(args.private/'capture.cid'),'--pull=never','--platform=linux/arm64',
        '--label','org.cachy-asahi.glibc16k.job='+args.job_token,'--user',f'{os.getuid()}:{os.getgid()}',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=128','--memory=2g','--cpus=2',
        '--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--env=CACHY_GLIBC16K_CAPTURE=1','--env=PYTHONDONTWRITEBYTECODE=1']
    for source,dest,readonly in ((c.HERE,'/source',True),(args.source_root,'/repo',True),
        (args.source_root/'scripts/ci/glibc-owned-runtime','/runtime',True),(stage,'/'+c.PREFIX,True),
        (args.base_dir/'installed-packages.lock','/expected.lock',True),(folder,'/work',False)):
        command+=['--mount','type=bind,src='+str(source)+',dst='+dest+(',readonly' if readonly else '')]
    return command+['--entrypoint=/usr/bin/python3',image,'-I','-B','/source/capture.py','--image',image,'--source',args.source_commit]


def retire(args,reuse,name,image,reserved):
    result=dict(capture_absent=not reserved,private_removed=False,producer='BORROWED_PRESERVED')
    if reserved:
        observed=reuse.query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}'])
        if observed:
            c.need(observed==name,'capture name ambiguous')
            cid=c.read(args.private/'capture.cid',128).decode().strip();c.need(re.fullmatch('[0-9a-f]{64}',cid),'exact capture CID required')
            rows=c.decode(reuse.query(['docker','container','inspect',cid]))
            c.need(len(rows)==1 and rows[0]['Id']==cid and rows[0]['Name']=='/'+name and rows[0]['Image']==image and
                   rows[0]['Config']['Labels'].get('org.cachy-asahi.glibc16k.job')==args.job_token,'capture ownership differs')
            reuse.query(['docker','container','rm','-f',cid])
            c.need(not reuse.query(['docker','container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}']),'capture CID remained')
        c.need(not reuse.query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'capture name remained')
        result['capture_absent']=True
    shutil.rmtree(args.private);result['private_removed']=not args.private.exists();return result


def trial(args):
    c.bindings();c.check_source(args.source_root);index,packages=c.pair(args.pair_root)
    c.need(args.execute,'explicit future CI execution required')
    reuse=c.load(args.source_root,'scripts/ci/tools-generic16k/run.py');image,owner=reuse.preflight(args)
    for path in (args.private,args.output):
        c.safe(path);c.need(not path.exists() and all(not path.is_relative_to(p) and not p.is_relative_to(path)
              for p in (args.source_root,args.base_dir,args.pair_root)),'fresh separate private/public paths')
    c.need(not args.private.is_relative_to(args.output) and not args.output.is_relative_to(args.private),'separate output/private paths')
    args.private.mkdir(mode=0o700);args.output.mkdir(mode=0o700)
    report=dict(status='FAIL',scope='PRIVATE_LOADER_GNU243CAA1_3_GENERIC16K_ONLY',job_token=args.job_token,image_id=image,
        source_commit=args.source_commit,pair_source=c.decode(c.read(c.HERE/'input-policy.json'))['pair_source'],pair_sha256=c.PACKAGE_SHA,
        hardware='NOT_RUN',performance='NOT_MEASURED',installation='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED',actors=[])
    name='glibc16k-capture-'+args.job_token;reserved=False
    try:
        generic=c.load(args.source_root,'scripts/virtual/generic16k/fixture.py');stage=args.private/'candidate'
        stage_rows=c.stage(packages[0],stage,generic)
        folder=args.private/'capture';folder.mkdir(mode=0o700)
        c.need(not reuse.query(['docker','container','ls','-a','--filter','name=^/'+name+'$','--format','{{.Names}}']),'fresh capture name required')
        c.save(args.private/'owner.json',dict(name=name,image=image,job_token=args.job_token));reserved=True
        code,_,actor=reuse.supervise(capture_command(args,image,name,folder,stage),args.private/'capture.log',240)
        report['actors'].append(actor);c.need(code==0,'native compile-only capture failed')
        raw=c.read(folder/'capture.json');receipt=c.decode(raw)
        c.need(receipt['image_id']==image and receipt['source_commit']==args.source_commit,'capture source/image lineage differs')
        files=payload(folder/'payload.tar',receipt,stage_rows,generic,args.source_root);report['capture']=receipt
        kr=c.decode(c.read(args.kernel_receipt,65536));kernel=reuse.kernel(kr,args.source_root);report['kernel']=kr
        copied=args.private/'Image';shutil.copyfile(kernel,copied);c.need(c.sha(c.read(copied,256*1024**2))==kr['image']['sha256'],'kernel copy identity differs')
        nonce=secrets.token_hex(16);release=kr['kernel_release']
        files.update({'init':(stat.S_IFREG|0o755,init(nonce,release)),'payload.json':(stat.S_IFREG|0o644,raw),
            'page-data':(stat.S_IFREG|0o444,b'A'*16384+b'B'*16384),
            'etc/passwd':(stat.S_IFREG|0o644,b'root:x:0:0:private init:/tmp:/usr/bin/bash\nfixture:x:23001:23001:private GNU trial:/tmp/glibc16k:/usr/bin/bash\n'),
            'etc/group':(stat.S_IFREG|0o644,b'root:x:0:\nfixture:x:23001:\n'),'etc/nsswitch.conf':(stat.S_IFREG|0o644,b'passwd: files\ngroup: files\n'),
            'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')})
        ramfs=args.private/'initramfs.cpio';ramfs.write_bytes(generic.cpio(files));c.need(ramfs.stat().st_size<=300*1024**2,'initramfs bound')
        qemu=shutil.which('qemu-system-aarch64');c.need(qemu,'accepted QEMU tool required')
        argv=[qemu,'-nodefaults','-machine','virt','-accel','tcg','-cpu','max','-smp','1','-m','1024','-kernel',str(copied),
              '-initrd',str(ramfs),'-append',generic.boot_arguments(True)+' glibc16k=1','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot']
        code,uart,actor=reuse.supervise(argv,args.private/'uart.log',900);report['actors'].append(actor)
        diagnostics=[line[len(b'GLIBC16K-DIAGNOSTIC '):] for line in uart.splitlines() if line.startswith(b'GLIBC16K-DIAGNOSTIC ')]
        c.need(len(diagnostics)<=1 and all(len(line)<=16384 for line in diagnostics),'closed bounded guest failure diagnostic')
        if diagnostics:report['guest_failure_diagnostic']=c.decode(diagnostics[0])
        report.update(guest=guest_report(uart,code,nonce,release,receipt),natural_VM_exit=True,QEMU_exit=code,
                      status='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT')
    except BaseException as error:report.update(status='FAIL',error_type=type(error).__name__,reason=str(error)[:400])
    finally:
        report['log_tails']={}
        report['compile_diagnostics']={}
        for number in range(1,14):
            path=args.private/'capture/clients'/('command-%02d.stderr'%number)
            if path.is_file() and not path.is_symlink():
                raw=c.read(path,262144)
                if raw:report['compile_diagnostics'][str(number)]=dict(bytes=len(raw),sha256=c.sha(raw),tail_base64=base64.b64encode(raw[-1024:]).decode())
        for name_ in ('capture.log','uart.log'):
            log=args.private/name_
            if log.is_file():
                data=c.read(log);report['log_tails'][name_]=dict(bytes=len(data),tail_base64=base64.b64encode(data[-8192:]).decode())
        previous=signal.getsignal(signal.SIGALRM)
        def expired(*_):raise TimeoutError('owned consumer cleanup deadline')
        signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,90)
        try:
            report['consumer_cleanup']=retire(args,reuse,name,image,reserved)
            c.need(owner.inspect_image(image,args.job_token)['Id']==image,'borrowed producer image changed')
        except BaseException as error:report.update(status='FAIL',cleanup_error=str(error)[:256])
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        c.save(args.output/'runtime.json',report)
    return report


def cleanup_safe(args):
    path=args.output/'runtime.json'
    if not path.exists():return not args.private.exists()
    report=c.decode(c.read(path,2*1024**2));row=report.get('consumer_cleanup',{})
    return report.get('job_token')==args.job_token and row.get('capture_absent') is True and row.get('private_removed') is True


def finalize(args):
    c.need(cleanup_safe(args),'consumer retirement must precede producer cleanup')
    report=c.decode(c.read(args.output/'runtime.json',2*1024**2));base=c.decode(c.read(args.base_dir/'report.json'))
    try:
        cleanup=base['owned_cleanup'];c.guest_receipt(report['guest'])
        c.need(report['status']=='PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT' and report['natural_VM_exit'] is True and report['QEMU_exit']==0 and
               len(report['actors'])==2 and all(r['natural_exit'] and r['exit']==0 and r['group_absent'] for r in report['actors']) and
               cleanup['status']=='PASS' and cleanup['probe']['absence_verified'] is True and cleanup['image']['absence_verified'] is True and
               cleanup['image']['id']==report['image_id'] and base['ownership']['token']==args.job_token,'normal consumer/producer retirement required')
        work=args.kernel_work
        c.safe(work);c.need(work==Path(os.environ['RUNNER_TEMP'])/'tools16k-kernel' and work.stat().st_uid==os.getuid() and
            Path(report['kernel']['helper']['path'])==work/'helper/build_kernel.py' and report['kernel']['kernel_build']=='PASS','owned completed kernel workspace required')
        shutil.rmtree(work);c.need(not work.exists(),'owned kernel workspace remained')
        report.update(status='PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP',producer_cleanup=cleanup,kernel_work_removed=True)
    except BaseException as error:report.update(status='FAIL',finalize_error=str(error)[:256])
    c.save(args.output/'runtime.json',report);return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('trial','cleanup-safe','finalize'))
    for name in ('source-root','base-dir','output','private'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--job-token',required=True)
    for name in ('pair-root','kernel-receipt','kernel-work'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--source-commit');parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    def interrupted(*_):raise KeyboardInterrupt('owned glibc16K controller interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    if args.mode=='cleanup-safe':raise SystemExit(0 if cleanup_safe(args) else 1)
    value=trial(args) if args.mode=='trial' else finalize(args)
    raise SystemExit(0 if value['status'] in ('PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT','PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP') else 1)
