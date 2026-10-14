"""Private bounded no-follow file/directory custody; no actor authorization."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import signal
import stat
import time


RECOVERY_BOUND=180


def need(value,code):
    if not value:raise ValueError(code)


def live(end):need(0<time.monotonic()<end,'original-deadline')
def identity(row):return(row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,row.st_size,row.st_mtime_ns,row.st_ctime_ns)


@contextmanager
def masked():
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM,signal.SIGALRM})
    try:yield
    finally:
        cause=__import__('sys').exc_info()[1]
        try:signal.pthread_sigmask(signal.SIG_SETMASK,previous)
        except BaseException:
            if cause is None:raise


class Files:
    def __init__(self):self.nodes=[];self.paths={};self.errors=[]

    def _hold(self,path,fd,mutable=False):
        try:
            need(len(self.nodes)<1536,'custody-node-cap')
            row=os.fstat(fd);node=[Path(path),fd,identity(row),mutable]
            self.nodes.append(node);self.paths[str(path)]=node
        except BaseException:
            try:os.close(fd)
            except BaseException:pass
            raise
        return node

    def directory(self,path,end,*,uid=None):
        path=Path(path)
        need(path.is_absolute()and '..'not in path.parts and len(path.parts)<=64,'directory-path')
        current=Path('/');parent=None
        for part in path.parts:
            live(end);current=Path('/')if part=='/'else current/part
            if str(current)in self.paths:parent=self.paths[str(current)][1];continue
            with masked():
                fd=os.open(current if parent is None else part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                node=self._hold(current,fd,True)
            parent=node[1];need(len(self.nodes)<=1536,'custody-node-cap')
        if uid is not None:need(os.fstat(parent).st_uid==uid,'directory-owner')
        self.verify(end);return parent

    def fresh(self,path,end):
        path=Path(path);parent=self.directory(path.parent,end,uid=os.getuid());live(end)
        with masked():
            os.mkdir(path.name,0o700,dir_fd=parent)
            created=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
            fd=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            node=self._hold(path,fd,True)
            need(node[2][:5]==identity(created)[:5]and stat.S_IMODE(node[2][2])==0o700,'fresh-directory-custody')
        self.verify(end);return path

    def file(self,path,end,*,sha=None,size=None,uid=None,mode=None,cap=2*1024**3):
        path=Path(path);parent=self.directory(path.parent,end);live(end)
        before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'regular-file')
        if uid is not None:need(before.st_uid==uid,'file-owner')
        if mode is not None:need(stat.S_IMODE(before.st_mode)==mode,'file-mode')
        with masked():
            node=self._hold(path,os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent))
        need(node[2]==identity(before),'file-open-drift')
        hasher=hashlib.sha256();position=0
        while position<before.st_size:
            live(end);block=os.pread(node[1],min(1024**2,before.st_size-position),position)
            need(block,'file-short-read');position+=len(block);hasher.update(block)
        self.verify(end)
        if size is not None:need(position==size,'file-size-pin')
        if sha is not None:need(hasher.hexdigest()==sha,'file-sha-pin')
        return node,hasher.hexdigest()

    def write(self,path,raw,end,*,mode=0o600):
        need(type(raw)is bytes and len(raw)<=8*1024**2,'owned-write-cap')
        path=Path(path);parent=self.directory(path.parent,end,uid=os.getuid());live(end)
        with masked():
            fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=parent)
            node=self._hold(path,fd,True);os.fchmod(fd,mode)
        offset=0
        while offset<len(raw):
            live(end);count=os.write(fd,raw[offset:]);need(count>0,'owned-short-write');offset+=count
        os.fsync(fd);live(end)
        node[2]=identity(os.fstat(fd));node[3]=False
        self.verify(end);return path

    def copy(self,node,target,end,mode=0o644):
        self.verify(end);path=Path(target);parent=self.directory(path.parent,end,uid=os.getuid())
        with masked():
            fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode,dir_fd=parent)
            new=self._hold(path,fd,True);os.fchmod(fd,mode)
        offset=0
        while offset<node[2][6]:
            live(end);block=os.pread(node[1],min(1024**2,node[2][6]-offset),offset);need(block,'copy-short-read')
            written=0
            while written<len(block):
                live(end);count=os.write(fd,block[written:]);need(count>0,'copy-short-write');written+=count
            offset+=len(block)
        os.fsync(fd);new[2]=identity(os.fstat(fd));new[3]=False;self.verify(end);return path

    def journal(self,path,end):
        path=Path(path);parent=self.directory(path.parent,end,uid=os.getuid())
        with masked():
            node=self._hold(path,os.open(path.name,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent),True)
            os.fchmod(node[1],0o600);node[2]=identity(os.fstat(node[1]))
        total=[0]
        def append(raw):
            need(type(raw)is bytes and len(raw)<=256*1024 and total[0]+len(raw)+1<=32*1024**2,'journal-cap')
            self.verify(end);data=raw+b'\n';position=0
            while position<len(data):
                live(end);count=os.write(node[1],data[position:]);need(count>0,'journal-short-write');position+=count
            os.fsync(node[1]);total[0]+=len(data);self.verify(end)
        return append

    def verify(self,end):
        for path,fd,before,mutable in self.nodes:
            live(end);held=identity(os.fstat(fd));named=identity(os.stat(path,follow_symlinks=False))
            width=5 if mutable or stat.S_ISDIR(before[2])else 9
            need(held[:width]==named[:width]==before[:width],'custody-drift')
        live(end)

    def close(self,*,end):
        # Missing/expired recovery authority cannot start identity/close actors.
        remaining=[]
        for node in reversed(self.nodes):
            path,fd,before,mutable=node
            try:
                live(end());need(identity(os.fstat(fd))[:2]==before[:2],'retirement-foreign')
                live(end());os.close(fd);self.paths.pop(str(path),None)
            except BaseException as error:
                self.errors.append(type(error).__name__);remaining.append(node)
        self.nodes=list(reversed(remaining));return list(self.errors)
