# SPDX-License-Identifier: MIT
"""Root-owned compile inputs/outputs; native methods are deferred actor boundaries."""
import hashlib
import math
import os
from pathlib import Path
import stat
import time

class Refused(ValueError):
    pass

def need(value,code):
    if not value:raise Refused(code)

def identity(s):
    return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink'))

class Workspace:
    """Root transfers fresh held input/output directories and ancestor custody.

    Inputs are Root-owned and unavailable for child writes; outputs are the one
    unprivileged child's private cwd. No directory allocation/privilege issuer or
    generic path API exists here. Root retains its separately admitted ancestors.
    """
    def __init__(self,*,admission,expected_admission,ancestry,expected_ancestry,
                 input_fd,input_path,output_fd,output_path,child_uid,child_gid,
                 work_end,cleanup_end,cancel,cancel_types=(KeyboardInterrupt,),os_api=os,clock=time.monotonic):
        need(type(admission) is object and admission is expected_admission
             and type(ancestry) is object and ancestry is expected_ancestry,'Root-workspace-grant')
        need(all(type(e) in (int,float) and math.isfinite(e) for e in (work_end,cleanup_end))
             and work_end<cleanup_end,'workspace-original-frame')
        need(type(child_uid) is int and child_uid>0 and type(child_gid) is int and child_gid>0,'child-owner')
        self.os,self.clock,self.cancel=os_api,clock,cancel
        self.cancel_types=cancel_types
        self.work_end,self.cleanup_end=work_end,cleanup_end
        self.paths=dict(inputs=str(Path(input_path)),outputs=str(Path(output_path)))
        need(all(Path(p).is_absolute() and '..' not in Path(p).parts for p in self.paths.values())
             and self.paths['inputs']!=self.paths['outputs'],'workspace-paths')
        self.directories=dict(inputs=input_fd,outputs=output_fd)
        self.uid,self.gid=child_uid,child_gid
        self.owned={};self.named={};self.command_binding=None
        self.closed=False;self.close_uncertain=False;self.cancelled=False
        self.last=None
        for role,fd in self.directories.items():
            need(type(fd) is int and fd>=0 and fd not in self.owned,'directory-FD')
            row=self.os.fstat(fd);need(stat.S_ISDIR(row.st_mode),'directory-type')
            owner=(0,0) if role=='inputs' else (child_uid,child_gid)
            mode=0o755 if role=='inputs' else 0o700
            need((row.st_uid,row.st_gid)==owner and stat.S_IMODE(row.st_mode)==mode,'directory-owner-mode')
            self.owned[fd]=identity(row)
        self.guard(work_end)

    def live(self,end,cleanup=False):
        now=self.clock();need(type(now) in (int,float) and math.isfinite(now)
                             and (self.last is None or now>=self.last),'workspace-clock')
        self.last=now
        if not cleanup:self.cancel()
        need(now<end,'workspace-deadline')

    def guard(self,end,cleanup=False):
        self.live(end,cleanup)
        need(not self.closed,'workspace-closed')
        for role,fd in self.directories.items():
            need(identity(self.os.fstat(fd))==self.owned[fd]
                 ==identity(self.os.stat(self.paths[role],follow_symlinks=False)),'directory-held-named-drift')
        self.live(end,cleanup)

    def path(self,role,name):
        need(role in self.paths and type(name) is str and name and '/' not in name and '\0' not in name
             and name not in ('.','..') and len(name)<=96,'compile-leaf')
        return self.paths[role]+'/'+name

    def _register(self,fd,role,name):
        need(fd not in self.owned,'workspace-FD-collision')
        self.owned[fd]=None;self.named[fd]=(role,name)
        self.owned[fd]=identity(self.os.fstat(fd))
        need(len(self.owned)<=40,'workspace-FD-budget')
        return fd

    def put_source(self,name,raw):
        self.guard(self.work_end);need(type(raw) is bytes and 0<len(raw)<=65536,'source-bound')
        self.path('inputs',name)
        fd=self.os.open(name,self.os.O_RDWR|self.os.O_CREAT|self.os.O_EXCL|self.os.O_NOFOLLOW|self.os.O_NONBLOCK,
                        0o444,dir_fd=self.directories['inputs'])
        self._register(fd,'inputs',name)
        row=self.os.fstat(fd);need((row.st_uid,row.st_gid)==(0,0) and stat.S_IMODE(row.st_mode)==0o444,'source-owner')
        offset=0
        while offset<len(raw):
            self.live(self.work_end);count=self.os.write(fd,raw[offset:offset+65536])
            need(type(count) is int and 0<count<=len(raw)-offset,'source-write');offset+=count
        need(self.read_fd(fd,len(raw),self.work_end)==raw,'source-held-readback')
        self.guard(self.work_end)

    def capture(self,name):
        self.guard(self.work_end);self.path('outputs',name)
        fd=self.os.open(name,self.os.O_RDWR|self.os.O_CREAT|self.os.O_EXCL|self.os.O_NOFOLLOW|self.os.O_NONBLOCK,
                        0o600,dir_fd=self.directories['outputs'])
        self._register(fd,'outputs',name)
        row=self.os.fstat(fd);need((row.st_uid,row.st_gid)==(0,0) and row.st_size==0
                                  and stat.S_IMODE(row.st_mode)==0o600,'capture-owner')
        return fd,self.owned[fd]

    def read_fd(self,fd,bound,end):
        self.guard(end);before=self.os.fstat(fd)
        need(fd in self.owned and identity(before)==self.owned[fd] and stat.S_ISREG(before.st_mode)
             and before.st_nlink==1 and 0<=before.st_size<=bound,'held-output')
        role,name=self.named[fd]
        named=self.os.stat(name,follow_symlinks=False) if role=='tool' else self.os.stat(name,dir_fd=self.directories[role],follow_symlinks=False)
        need(identity(named)==identity(before),
             'output-held-named')
        raw=bytearray()
        while True:
            self.live(end);part=self.os.pread(fd,min(65536,bound+1-len(raw)),len(raw))
            if not part:break
            raw.extend(part);need(len(raw)<=bound,'output-bound')
        after=self.os.fstat(fd)
        need(identity(after)==identity(before) and before.st_size==after.st_size==len(raw)
             and before.st_mtime_ns==after.st_mtime_ns and before.st_ctime_ns==after.st_ctime_ns,'output-drift')
        self.guard(end);return bytes(raw)

    def tool(self,path,row,sample):
        """Root selected actual row first; passive resampling never grants use."""
        self.guard(self.work_end)
        observed=sample(path,self.work_end)
        need(observed is not None and observed['canonical']==path
             and observed['row']=={k:row[k] for k in ('bytes','mode','sha256')}
             and row['mode']==0o755,'selected-tool-reobservation')
        fd=self.os.open(path,self.os.O_RDONLY|self.os.O_NOFOLLOW|self.os.O_NONBLOCK)
        self._register(fd,'tool',path);info=self.os.fstat(fd)
        need((info.st_uid,info.st_gid)==(0,0) and stat.S_IMODE(info.st_mode)==0o755
             and not info.st_mode&(stat.S_ISUID|stat.S_ISGID),'tool-owner')
        raw=self.read_fd(fd,64*1024**2,self.work_end)
        need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'held-selected-tool-bytes')
        return fd,self.owned[fd]

    def absent_output(self,name):
        self.guard(self.work_end);self.path('outputs',name)
        try:self.os.stat(name,dir_fd=self.directories['outputs'],follow_symlinks=False)
        except FileNotFoundError:return True
        raise Refused('fresh-output-required')

    def output(self,name,bound):
        self.guard(self.work_end);self.path('outputs',name)
        fd=self.os.open(name,self.os.O_RDONLY|self.os.O_NOFOLLOW|self.os.O_NONBLOCK,dir_fd=self.directories['outputs'])
        self._register(fd,'outputs',name);row=self.os.fstat(fd)
        need((row.st_uid,row.st_gid)==(self.uid,self.gid) and not row.st_mode&0o022
             and not row.st_mode&(stat.S_ISUID|stat.S_ISGID),'compiled-output-owner')
        raw=self.read_fd(fd,bound,self.work_end)
        return raw,dict(bytes=len(raw),mode=stat.S_IMODE(row.st_mode),sha256=hashlib.sha256(raw).hexdigest())

    def retire(self):
        need(not self.closed,'workspace-retirement-once');self.closed=True;first=None
        for fd,expected in reversed(tuple(self.owned.items())):
            try:
                self.live(self.cleanup_end,True)
                need(identity(self.os.fstat(fd))==expected,'foreign-FD-never-closed')
                self.os.close(fd)
            except BaseException as error:
                self.close_uncertain=True
                if first is None:first=error
                self.cancelled|=isinstance(error,self.cancel_types)
        if first is not None:raise first
        return True
