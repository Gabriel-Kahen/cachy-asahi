#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dedicated system-path callbacks over the unchanged private16K owner/controller."""
import base64
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as c


def adapted_source(root):
    raw=c.read(Path(root)/'scripts/ci/glibc-generic16k/run.py').decode()
    for before,after in (
        ('GLIBC16K','SYSTEM16K'),('glibc16k=1','glibcsystem16k=1'),('org.cachy-asahi.glibc16k.job','org.cachy-asahi.glibc-system16k.job'),('glibc16k-capture-','glibcsystem16k-capture-'),
        ('PRIVATE_LOADER_GNU243CAA1_3_GENERIC16K_ONLY','DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION'),('PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP','PASS_GNU_SYSTEM_PATHS_GENERIC16K_AND_ORDERED_CLEANUP'),
        ("c.decode(c.read(c.HERE/'input-policy.json'))['pair_source']","c.bindings()['binding']['source']")):
        c.need(before in raw,'fixed inherited system16K adapter anchor absent: '+before);raw=raw.replace(before,after)
    before='/smoke || fail\n';after=before+'''/usr/bin/mount -t proc -o ro,nosuid,nodev,noexec proc /system/proc || fail
/usr/bin/mount -t devtmpfs -o nosuid devtmpfs /system/dev || fail
''';c.need(raw.count(before)==1,'one static probe before target mounts required');raw=raw.replace(before,after)
    before="'proc':(stat.S_IFDIR|0o555,b''),'dev':(stat.S_IFDIR|0o755,b''),'tmp':(stat.S_IFDIR|0o1777,b'')";c.need(raw.count(before)==1,'one closed cpio root extension required')
    after=before+",'system/lib':(stat.S_IFLNK|0o777,b'usr/lib'),'system/proc':(stat.S_IFDIR|0o555,b''),'system/dev':(stat.S_IFDIR|0o755,b''),'system/tmp':(stat.S_IFDIR|0o1777,b'')"
    raw=raw.replace(before,after)
    return raw


def payload(archive,receipt,stage_rows,generic,root):
    c.need(receipt['status']=='CAPTURED_CONVENTIONAL_PROVIDER_AND_PRECOMPILED_NORMAL_CLIENTS' and receipt['inventory_sha256']==c.LOCK and receipt['pair_sha256']==c.PACKAGE_SHA and receipt['archive']==dict(bytes=archive.stat().st_size,sha256=c.sha(c.read(archive,270*1024**2))),'exact normal-client/candidate capture lineage required')
    files={};total=0;elfs={}
    with tarfile.open(archive,'r:') as stream:
        for entry in stream:
            name=c.relative(entry.name);c.need(entry.isfile() and entry.uid==entry.gid==0 and name not in files and len(files)<4096 and entry.size<=64*1024**2,'ordinary bounded captured members')
            raw=stream.extractfile(entry).read();total+=len(raw);row=receipt['files'][name]
            c.need(total<=256*1024**2 and len(raw)==entry.size==row['bytes'] and entry.mode==row['mode'] and c.sha(raw)==row['sha256'],'captured bytes/mode differ')
            files[name]=(stat.S_IFREG|entry.mode,raw)
            if raw.startswith(b'\x7fELF'):elfs[name]=dict(c.aligned(raw,generic),scope='candidate' if name.startswith('system/') else 'bootstrap')
    c.need(set(files)==set(receipt['files']) and elfs==receipt['elf'],'complete captured file/ELF set')
    actual={n.removeprefix('system/'):r for n,r in receipt['files'].items() if n.startswith('system/') and not n.startswith('system/'+c.FIXTURE+'/')}
    c.need({n:{k:r[k] for k in ('bytes','mode','sha256')} for n,r in actual.items()}==stage_rows,'actual accepted conventional stage differs')
    for name in c.CLIENTS:
        key='system/'+c.FIXTURE+'/'+name;expected=c.INDEX['probes'][name];c.need(len(files[key][1])==expected['bytes'] and c.sha(files[key][1])==expected['sha256'],'actual accepted normal client changed')
    for side in ('a','b'):
        c.need(receipt['normal_compile'][side]==c.decode(c.read(c.ref(c.PACKET,c.NORMAL_REFS[side]),2*1024**2)),'reused normal compile lineage differs')
    c.need(c.decode(files['normal-compile.json'][1])==receipt['normal_compile'],'normal receipts/capture join')
    for name in ('guest.py','enter-system.py'):c.need(files[name][1]==c.read(c.HERE/name),'exact new wrapper bytes')
    c.need(files['runtime/runner.py'][1]==c.read(Path(root)/'scripts/ci/glibc-owned-runtime/runner.py') and files['runtime/provider-validator.py'][1]==c.validator_source(root).encode(),'unchanged supervisor/narrow normal validator bytes')
    c.need(c.sha(files['recovery/held-glibc.pkg.tar.xz'][1])==c.HELD_SHA and set(receipt['bootstrap_roles'])==set(c.ROLES),'held rollback archive/role set changed')
    held=generic.Archive(c.ref(c.PACKET,c.INDEX['held'],256*1024**2))
    try:
        for role,name in c.ROLES.items():
            raw=files[name][1];c.need(raw==held.read(name)[1] and receipt['bootstrap_roles'][role]==dict(path=name,sha256=c.sha(raw)),'actual held bootstrap role bytes differ')
    finally:held.tar.close()
    c.elf_closure(elfs,files)
    c.need({'smoke','usr/bin/python3',*['usr/bin/'+n for n in c.TOOLS]}<=set(files),'bootstrap/probe closure roots')
    return files


def guest_report(uart,code,nonce,release,capture):
    c.need(code==0 and len(uart)<=1024**2 and b'SMOKE16K: mmap,mprotect,file-offset PASS' in uart,'natural VM exit and actual page probe required')
    lines=[r.rstrip(b'\r') for r in uart.splitlines() if r.startswith(b'SYSTEM16K ')];prefix=('SYSTEM16K REPORT '+nonce+' ').encode()
    c.need(len(lines)==3 and lines[0]==('SYSTEM16K BOOT '+nonce+' 16384').encode() and lines[1].startswith(prefix) and lines[2]==('SYSTEM16K PASS '+nonce).encode(),'nonce-bound complete ordered system16K protocol')
    raw=base64.b64decode(lines[1][len(prefix):],validate=True);c.need(len(raw)<=512*1024,'guest receipt cap');value=c.decode(raw);c.guest_receipt(value);c.need(value['kernel']==release,'actual kernel release differs')
    for name,row in value['runtime_files'].items():
        key='system/'+name.lstrip('/');expected=capture['files'].get(key);c.need(expected and row['sha256']==expected['sha256'] and row['bytes']==expected['bytes'],'guest mapped an uncaptured normal system file')
    return value


def capture_command(args,image,name,folder,stage):
    argv=['docker','run','--name',name,'--cidfile',str(args.private/'capture.cid'),'--pull=never','--platform=linux/arm64','--label','org.cachy-asahi.glibc-system16k.job='+args.job_token,'--user',f'{os.getuid()}:{os.getgid()}','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--network=none','--pids-limit=128','--memory=2g','--cpus=2','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=128m','--env=CACHY_GLIBC_SYSTEM16K_CAPTURE=1','--env=PYTHONDONTWRITEBYTECODE=1']
    for source,dest,readonly in ((c.HERE,'/source',True),(args.source_root,'/repo',True),(args.source_root/'scripts/ci/glibc-owned-runtime','/runtime',True),(stage,'/system',True),(args.pair_root,'/inputs',True),(args.base_dir/'installed-packages.lock','/expected.lock',True),(folder,'/work',False)):
        argv+=['--mount','type=bind,src='+str(source)+',dst='+dest+(',readonly' if readonly else '')]
    return argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/source/capture.py','--image',image,'--source',args.source_commit]


def namespace(root):
    value=dict(__file__=str(c.HERE/'run.py'),__name__='accepted_system16k_controller');exec(compile(adapted_source(root),value['__file__'],'exec'),value);value.update(c=c,payload=payload,guest_report=guest_report,capture_command=capture_command)
    original=value['finalize']
    def finalize(args):
        c.bindings();c.check_source(args.source_root);return original(args)
    value['finalize']=finalize;return value


if __name__=='__main__':
    # The original parser/entry path is used; callbacks above supply only the
    # standard-root payload, input gate and exact normal-runtime validation.
    value=namespace(c.SOURCE)
    import argparse,signal
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('trial','cleanup-safe','finalize'))
    for name in ('source-root','base-dir','output','private'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--job-token',required=True)
    for name in ('pair-root','kernel-receipt','kernel-work'):p.add_argument('--'+name,type=Path)
    p.add_argument('--source-commit');p.add_argument('--execute',action='store_true');a=p.parse_args()
    def interrupted(*_):raise KeyboardInterrupt('owned system16K controller interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    if a.mode=='cleanup-safe':raise SystemExit(0 if value['cleanup_safe'](a) else 1)
    result=value['trial'](a) if a.mode=='trial' else value['finalize'](a)
    raise SystemExit(0 if result['status'] in ('PASS_SMOKE_AWAITING_PRODUCER_RETIREMENT','PASS_GNU_SYSTEM_PATHS_GENERIC16K_AND_ORDERED_CLEANUP') else 1)
