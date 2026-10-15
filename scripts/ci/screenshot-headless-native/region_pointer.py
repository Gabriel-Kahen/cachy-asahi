# SPDX-License-Identifier: MIT
"""Finite Wayland virtual pointer on the trial's private socket; no host input."""
import array
import hashlib
import os
from pathlib import Path
import socket
import stat
import struct
import time

def need(ok,reason):
    if not ok:raise ValueError(reason)

def uint(*values):
    need(all(type(v) is int and 0<=v<2**32 for v in values),'wire uint bounds')
    return struct.pack('='+str(len(values))+'I',*values)

def string(value):
    b=value.encode('ascii')+b'\0';need(len(b)<=128,'wire string bound')
    return uint(len(b))+b+b'\0'*((-len(b))%4)

class Reader:
    def __init__(self,data):self.data=data;self.offset=0
    def word(self):
        need(self.offset+4<=len(self.data),'wire truncated uint')
        value=struct.unpack_from('=I',self.data,self.offset)[0];self.offset+=4;return value
    def text(self):
        size=self.word();end=self.offset+size;aligned=(end+3)&~3
        need(0<size<=128 and aligned<=len(self.data),'wire string size')
        raw=self.data[self.offset:end]
        need(raw[-1:]==b'\0' and b'\0' not in raw[:-1] and not any(self.data[end:aligned]),'wire string terminator/padding')
        self.offset=aligned;return raw[:-1].decode('ascii')
    def done(self):need(self.offset==len(self.data),'wire trailing payload')

class Pointer:
    def __init__(self,path,deadline,peer_pid,trace):
        root=Path('/tmp/screenshot-runtime');path=Path(path)
        need(path.parent==root and path.name.startswith('wayland-'),'private Wayland path')
        parent=root.lstat();node=path.lstat()
        need(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode)==0o700 and parent.st_uid==os.getuid(),'private runtime owner/mode')
        need(stat.S_ISSOCK(node.st_mode) and node.st_uid==os.getuid(),'owned Wayland socket')
        self.deadline=deadline;self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.objects={1:'display'};self.next_id=2;self.globals={};self.trace=trace;self.capabilities=None;self.pointer=None;self.closed=False
        try:
            self.sock.settimeout(self.left());self.sock.connect(str(path))
            pid,uid,gid=struct.unpack('=iII',self.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(pid==peer_pid and uid==os.getuid() and gid==os.getgid(),'owned compositor peer credentials')
            need((path.lstat().st_dev,path.lstat().st_ino)==(node.st_dev,node.st_ino),'Wayland socket changed')
            self.registry=self.allocate('registry');self.send(1,1,uint(self.registry));self.roundtrip()
            self.seat=self.bind('wl_seat',2,'seat');self.output=self.bind('wl_output',2,'output')
            self.manager=self.bind('zwlr_virtual_pointer_manager_v1',2,'manager');self.roundtrip()
            self.before=self.capabilities;need(self.before==0,'fresh seat has no input capability')
            self.pointer=self.allocate('virtual_pointer');self.send(self.manager,2,uint(self.seat,self.output,self.pointer));self.roundtrip()
            need(self.capabilities==1,'actual seat POINTER-only capability required')
        except BaseException:
            self.sock.close();self.closed=True;raise
    def left(self):
        n=self.deadline-time.monotonic();need(n>0,'virtual pointer deadline');return min(n,3)
    def allocate(self,kind):
        need(self.next_id<128,'finite Wayland objects');i=self.next_id;self.next_id+=1;self.objects[i]=kind;return i
    def send(self,obj,opcode,payload=b''):
        need(obj in self.objects and 0<=opcode<65536 and len(payload)%4==0 and len(payload)+8<=4096,'wire request bounds')
        self.sock.settimeout(self.left());self.sock.sendall(uint(obj,((len(payload)+8)<<16)|opcode)+payload)
        self.record('send',obj,opcode,payload)
    def record(self,direction,obj,opcode,payload):
        need(len(self.trace)<1024,'finite virtual pointer trace')
        self.trace.append({'direction':direction,'object':obj,'interface':self.objects.get(obj),'opcode':opcode,'bytes':len(payload),'payload_sha256':hashlib.sha256(payload).hexdigest()})
    def exact(self,n):
        data=bytearray()
        while len(data)<n:
            self.sock.settimeout(self.left())
            b,anc,flags,_=self.sock.recvmsg(n-len(data),socket.CMSG_SPACE(16*4))
            for level,kind,payload in anc:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    fds=array.array('i');fds.frombytes(payload[:len(payload)//fds.itemsize*fds.itemsize])
                    for fd in fds:os.close(fd)
            need(not anc and not flags,'unexpected Wayland ancillary data');need(b,'Wayland EOF');data.extend(b)
        return bytes(data)
    def event(self):
        obj,word=struct.unpack('=II',self.exact(8));size,opcode=word>>16,word&65535
        need(8<=size<=4096 and size%4==0 and obj in self.objects,'wire event header')
        body=self.exact(size-8);kind=self.objects[obj];self.record('receive',obj,opcode,body);r=Reader(body)
        if kind=='display':
            if opcode==0:
                failed=r.word();code=r.word();message=r.text();r.done();raise ValueError('Wayland protocol error '+str((failed,code,message)))
            need(opcode==1,'display event opcode');deleted=r.word();r.done();need(deleted in self.objects and deleted!=1,'delete known ID');self.objects.pop(deleted)
        elif kind=='registry':
            need(opcode==0,'registry removal/unknown event');name=r.word();interface=r.text();version=r.word();r.done()
            need(name not in self.globals and len(self.globals)<256 and version>0,'registry bounds/duplicate')
            self.globals[name]=(interface,version)
        elif kind=='seat':
            if opcode==0:self.capabilities=r.word();need(self.capabilities<=7,'seat capability bits')
            elif opcode==1:self.seat_name=r.text()
            else:raise ValueError('seat event opcode')
            r.done()
        elif kind=='callback':need(opcode==0,'callback event opcode');r.word();r.done();return obj
        elif kind=='output':need(opcode in {0,1,2,3},'output event opcode')
        else:raise ValueError('unexpected event interface')
        return None
    def roundtrip(self):
        callback=self.allocate('callback');self.send(1,0,uint(callback))
        for _ in range(512):
            if self.event()==callback:return
        raise ValueError('finite Wayland roundtrip event cap')
    def bind(self,name,version,kind):
        matches=[(i,v) for i,(interface,v) in self.globals.items() if interface==name]
        need(len(matches)==1 and matches[0][1]>=version,'one compatible '+name)
        obj=self.allocate(kind);self.send(self.registry,0,uint(matches[0][0])+string(name)+uint(version,obj));return obj
    def position(self,x,y):
        need(type(x) is type(y) is int and 0<=x<320 and 0<=y<240,'virtual pointer output bounds')
        self.send(self.pointer,1,uint(self.timestamp(),2*x+1,2*y+1,640,480));self.send(self.pointer,4);self.roundtrip()
    def button(self,state):
        need(type(state) is int and state in (0,1),'left-button state')
        self.send(self.pointer,2,uint(self.timestamp(),272,state));self.send(self.pointer,4);self.roundtrip()
    def timestamp(self):return int(time.monotonic()*1000)&0xffffffff
    def close(self):
        if self.closed:return
        try:
            if self.pointer is not None:
                self.send(self.pointer,8);self.roundtrip();need(self.capabilities==0,'virtual pointer capability retirement')
            self.send(self.manager,1);self.roundtrip()
        finally:self.sock.close();self.closed=True
