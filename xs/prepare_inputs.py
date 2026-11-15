#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future admitted DATA preparation only; never invoke Perl, tools, or XS."""
import sys
if __name__ == '__main__' and (len(sys.argv)!=1 or not sys.flags.isolated or sys.flags.optimize or
        not sys.dont_write_bytecode or sys.version_info[:2]!=(3,14)):
    raise SystemExit('no arguments; isolated unoptimized Python3.14 with -B required')

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import time

SOURCE=Path('/source');BUNDLE=Path('/inputs');WORK=Path('/xs-work')
ARCHIVE='perl-5.42.3-1.3-aarch64.pkg.tar.zst'
ARCHIVE_BYTES=22071176
ARCHIVE_SHA='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22'
DECISION_SHA='27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1'
PREFLIGHT_SHA='9e881d5144c49cfa6b4a9abe5bc5172f0d4f00038d94e52426dc88b05473bc0d'
STREAM_SHA='10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838'
INVENTORY_SHA='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
MIB=1024**2


def need(value,why):
    if not value:raise ValueError(why)


def load(name,path,digest):
    raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==digest,'frozen Source helper differs')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def runtime():
    need(os.uname().machine=='aarch64' and os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001,'native alarm1001 preparation only')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(status[key].strip(),16)==0 for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and status['NoNewPrivs'].strip()=='1','actual cap0/NNP preparation')
    limits={key:Path('/sys/fs/cgroup',key).read_text().strip() for key in ('cpu.max','memory.max','memory.swap.max','pids.max')}
    need(limits=={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'},'actual preparation resource limits')
    mounts={}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left,_,right=line.partition(' - ');a,b=left.split(),right.split()
        if len(a)>=6 and len(b)==3 and a[4] in ('/','/source','/inputs','/xs-work'):
            need(a[4] not in mounts,'unique preparation mount');mounts[a[4]]=(set(a[5].split(',')),b[0],set(b[2].split(',')))
    need(set(mounts)=={'/','/source','/inputs','/xs-work'} and all('ro' in mounts[x][0] for x in ('/','/source')) and
         'rw' in mounts['/inputs'][0] and mounts['/xs-work'][1]=='tmpfs' and
         {'rw','nosuid','nodev'}<=mounts['/xs-work'][0] and 'noexec' not in mounts['/xs-work'][0] and
         {'uid=1001','gid=1001'}<=mounts['/xs-work'][2],'actual RO Source/RW bundle/exec scratch')
    scratch=os.statvfs(WORK);need(scratch.f_blocks*scratch.f_frsize==256*MIB,'actual256MiB scratch capacity')
    need(sorted(x.name for x in Path('/sys/class/net').iterdir())==['lo'],'actual no-network preparation')
    for root in (BUNDLE,WORK):
        s=root.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==1001 and not stat.S_IMODE(s.st_mode)&0o022,'owned protected preparation directory')
    return dict(uid=1001,gid=1001,architecture='aarch64',limits=limits,capabilities='ZERO',NoNewPrivs=1,network='LO_ONLY')


def scan(path,api,limits,selected,expected=None,prefix=None):
    """Two bounded DATA passes. No tar extraction API and no archive code import."""
    rows={};controls={};headers=0;ended=False;copied={};total=0
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            nonlocal headers,ended
            api.tick(limits);block=archive.fileobj.read(512)
            if block==bytes(512):ended=True
            else:headers+=1;need(headers<=8192,'raw archive header limit')
            item=(cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf')
                  else cls.frombuf(block,archive.encoding,archive.errors));item.offset=archive.fileobj.tell()-512
            return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'PAX body bound');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'long-name body bound');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse archive refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno());decoded=api.Decoded(source,limits,0)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==ARCHIVE_BYTES,'fixed regular archive')
        with tarfile.open(fileobj=decoded,mode='r|',bufsize=65536,tarinfo=Info,stream=True) as archive:
            for item in archive:
                api.tick(limits);name=api.relative(item.name.removeprefix('./').rstrip('/'))
                need(name not in rows and len(rows)<8192 and item.uid==item.gid==0 and not item.sparse and
                     not any(key.startswith('GNU.sparse') for key in item.pax_headers) and 0<=item.size<=32*MIB,'unique bounded ordinary package member')
                row=dict(mode=item.mode&0o7777)
                if item.isdir():row['type']='directory'
                elif item.issym():
                    need(not selected(name) and len(item.linkname)<=4096 and '\0' not in item.linkname,'selected runtime alias refused')
                    row.update(type='symlink',target=item.linkname)
                elif item.islnk():
                    target=api.relative(item.linkname.removeprefix('./'))
                    need(not selected(name) and target in rows and rows[target]['type']=='file','only ignored prior-regular-target hardlinks outside runtime')
                    row.update(type='hardlink',target=target)
                else:
                    need(item.isfile(),'archive special member refused')
                    body=archive.extractfile(item).read(32*MIB+1)
                    need(len(body)==item.size,'complete bounded regular member');row.update(type='file',bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                    if name in ('.PKGINFO','.BUILDINFO'):
                        need(len(body)<=MIB,'bounded package metadata');controls[name]=body
                    if selected(name):
                        total+=len(body);need(len(copied)<5000 and total<=128*MIB and row['mode'] in (0o644,0o755),'finite protected runtime files')
                        copied[name]={key:row[key] for key in ('bytes','sha256','mode')}
                        if prefix is not None:
                            need(expected.get(name)==row,'second-pass member differs')
                            target=prefix/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                            with target.open('xb') as out:out.write(body);os.fchmod(out.fileno(),row['mode'])
                rows[name]=row
            tail=archive.fileobj.read(65536);padding=0
            while tail:
                need(not any(tail),'zero-only complete tar tail');padding+=len(tail);tail=archive.fileobj.read(65536)
            need(ended and padding>=512 and decoded.done and decoded.total%512==0,'complete single-frame archive and tar end')
        identity=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(identity(before)==identity(os.fstat(source.fileno()))==identity(path.lstat()),'archive changed during bounded pass')
    if expected is not None:need(rows==expected,'whole second-pass archive description differs')
    return rows,controls,copied,dict(headers=headers,decoded_bytes=decoded.total,selected_files=len(copied),selected_bytes=total)


def main():
    deadline=time.monotonic()+90
    p=load('xs_preparation_preflight',SOURCE/'consumer/preflight.py',PREFLIGHT_SHA)
    archive=BUNDLE/ARCHIVE;decision=BUNDLE/'accepted-reader.json'
    need(p.pin(p.read(archive,64*MIB))==dict(bytes=ARCHIVE_BYTES,sha256=ARCHIVE_SHA),'Root-accepted exact ARM package bytes')
    raw=p.read(decision);need(p.pin(raw)==dict(bytes=5804,sha256=DECISION_SHA),'fixed opaque Root decision DATA')
    accepted=json.loads(raw)  # Exact externally pinned DATA includes fractional observed timings.
    pair=dict(source='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f',run='43692477455',job='132745843566')
    need(accepted['schema']==1 and accepted['issuer']=='Root' and accepted['accepted'] is True and
         accepted['status']=='ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY' and accepted['page_bytes']==4096 and
         accepted['archive']==dict(bytes=ARCHIVE_BYTES,sha256=ARCHIVE_SHA) and all(accepted['binding'][k]==v for k,v in pair.items()),'accepted exact ARM4K pair DATA binding')
    observed=runtime();os.umask(0o077)
    outputs=('prefix','xs-inputs.json','xs-admission.json','xs-plan.json','preparation.json')
    need(not any(os.path.lexists(BUNDLE/name) for name in outputs),'fresh one-shot prepared DATA outputs')
    api=load('xs_preparation_archive_stream',SOURCE/'held/perl/helpers/archive_stream.py',STREAM_SHA)
    limits=api.Limits(ARCHIVE_BYTES,ARCHIVE_BYTES,256*MIB,8192,32*MIB,64*MIB,deadline)
    selected=lambda name:name=='usr/bin/perl' or any(name==root or name.startswith(root+'/') for root in (p.ARCH,p.PURE))
    rows,metadata,files,first=scan(archive,api,limits,selected)
    need(rows.get('usr/bin/perl',{}).get('type')=='file' and files,'actual regular candidate runtime required')
    need(metadata.get('.PKGINFO')==p.read(BUNDLE/'PKGINFO') and metadata.get('.BUILDINFO')==p.read(BUNDLE/'BUILDINFO'),'sidecars match actual package control bytes')
    need(p.pin(p.read(BUNDLE/'packages.txt'))['sha256']==INVENTORY_SHA,'exact signed349 toolchain inventory')
    prefix=BUNDLE/'prefix';prefix.mkdir(mode=0o700)
    _,_,second_files,second=scan(archive,api,limits,selected,rows,prefix)
    need(second_files==files and p.pin(p.read(archive,64*MIB))==dict(bytes=ARCHIVE_BYTES,sha256=ARCHIVE_SHA),'copy and retained package remain exact')
    inputs=dict(schema=1,archive_sha256=ARCHIVE_SHA,candidate_recipe_sha256=p.CANDIDATE['recipe_sha256'],files=files)
    def emit(name,value):
        body=p.encode(value)
        with (BUNDLE/name).open('xb') as out:out.write(body)
        return p.pin(body)
    def operand(path,cap):return dict(path=str(path),**p.pin(p.read(path,cap)))
    def tool(path):
        actual=Path(path).resolve(strict=True);need(actual.parent==Path('/usr/bin') and os.access(actual,os.X_OK),'actual explicit native image tool')
        return operand(actual,16*MIB)
    input_pin=emit('xs-inputs.json',inputs);info=prefix.stat();cc=tool('/usr/bin/gcc')
    admission=dict(schema=1,candidate=p.CANDIDATE,target_arch='aarch64',root=dict(path=str(prefix),kind='extracted',owner_uid=info.st_uid,device=info.st_dev,inode=info.st_ino),
        archive=dict(name=ARCHIVE,**operand(archive,64*MIB)),metadata=dict(pkginfo=operand(BUNDLE/'PKGINFO',MIB),buildinfo=operand(BUNDLE/'BUILDINFO',MIB)),
        inventory=operand(BUNDLE/'packages.txt',MIB),inputs_sha256=input_pin['sha256'],toolchain=dict(cc=cc,ld=dict(cc),make=tool('/usr/bin/make')),
        artifact=dict(kind='native',**pair))
    admission_pin=emit('xs-admission.json',admission);stage=WORK/'xs-stage';need(not os.path.lexists(stage),'fresh DATA-only planning stage');stage.mkdir(mode=0o700)
    held=stage.stat()
    try:
        for name in p.FIXTURE:
            body=p.read(SOURCE/'consumer'/name);need(body==p.read(BUNDLE/'consumer'/name),'bundled frozen fixture bytes')
            target=stage/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(body)
        plan=p.plan(BUNDLE/'xs-admission.json',admission_pin['sha256'],BUNDLE/'xs-inputs.json',input_pin['sha256'],stage)
        plan_pin=emit('xs-plan.json',plan)
    finally:
        now=stage.lstat();need((now.st_dev,now.st_ino,now.st_uid)==(held.st_dev,held.st_ino,held.st_uid),'owned planning stage identity')
        shutil.rmtree(stage);need(not stage.exists(),'planning DATA stage removed')
    need(time.monotonic()<deadline,'fixed90-second preparation deadline')
    result=dict(schema=1,status='PREPARED_NATIVE_XS_DATA_ONLY',archive=operand(archive,64*MIB),accepted_reader=operand(decision,65536),root=admission['root'],
        inputs=input_pin,admission=admission_pin,plan=plan_pin,files=files,extraction=dict(first_pass=first,copy_pass=second,selected_aliases='REFUSED',ignored_hardlinks='PRIOR_REGULAR_TARGETS_ONLY'),
        runtime=observed,planning_stage_removed=True,native_acceptance=False,XS_acceptance=False,Perl_invocations=0,compiler_invocations=0,XS_loads=0)
    need(time.monotonic()<deadline,'fixed90-second preparation deadline')
    emit('preparation.json',result);print(p.encode(result).decode(),end='')


if __name__=='__main__':main()
