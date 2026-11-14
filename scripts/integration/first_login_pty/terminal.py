# SPDX-License-Identifier: MIT
"""Finite Linux PTY for this fixed shell journey; no fallback or ambient HOME."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import selectors
import signal
import struct
import subprocess
import termios
import time


def need(ok,why):
    if not ok:raise ValueError(why)


def members(sid):
    rows={}
    names=list(Path('/proc').iterdir());need(len(names)<=8192,'bounded process observation')
    for p in names:
        if not p.name.isdecimal():continue
        try:
            parts=(p/'stat').read_text().rsplit(')',1)[1].split()
            if int(parts[3])==sid:rows[int(p.name)]=(parts[0],int(parts[19]))
        except (FileNotFoundError,ProcessLookupError):pass
    return rows


class Terminal:
    def __init__(self,label,argv,env,cwd,out,signals,seconds=25,limit=131072):
        self.label,self.argv,self.env,self.cwd,self.out,self.signals=label,argv,env,cwd,Path(out),signals
        self.seconds,self.limit=seconds,limit
        self.master=self.slave=self.process=self.selector=None
        self.data=bytearray();self.actions=[];self.cursor=0;self.closed=False
        self.record=dict(label=label,argv=argv,seconds=seconds,output_limit=limit,status='FAIL',pty=True,actions=self.actions)

    def __enter__(self):
        try:
            with self.signals.spawn_signals() as restore:
                self.master,self.slave=pty.openpty()
                attrs=termios.tcgetattr(self.slave);attrs[3]&=~termios.ECHO
                termios.tcsetattr(self.slave,termios.TCSANOW,attrs)
                fcntl.ioctl(self.slave,termios.TIOCSWINSZ,struct.pack('HHHH',24,100,0,0))
                slave=self.slave
                def setup():
                    os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0);restore()
                self.process=subprocess.Popen(self.argv,stdin=slave,stdout=slave,stderr=slave,cwd=self.cwd,env=self.env,preexec_fn=setup)
                os.close(self.slave);self.slave=None
            self.sid=self.process.pid;self.deadline=time.monotonic()+self.seconds
            self.selector=selectors.DefaultSelector();self.selector.register(self.master,selectors.EVENT_READ)
            self.actions.append(dict(event='spawn',sid=self.sid))
            return self
        except BaseException:
            self.finish(False);raise

    def pump(self,seconds=.03):
        need(time.monotonic()<self.deadline,'PTY session deadline')
        if self.selector.select(min(seconds,max(.001,self.deadline-time.monotonic()))):
            try:raw=os.read(self.master,min(16384,self.limit-len(self.data)+1))
            except OSError as e:
                if e.errno!=errno.EIO:raise
                raw=b''
            if not raw:self.closed=True;return
            need(len(self.data)+len(raw)<=self.limit,'PTY output cap')
            self.data.extend(raw)

    def send(self,raw,event):
        need(type(raw) is bytes and 0<len(raw)<=16384,'finite literal PTY input')
        need(os.write(self.master,raw)==len(raw),'complete PTY input')
        self.actions.append(dict(event=event,bytes=len(raw),input_hex=raw.hex(),offset=len(self.data)))

    def expect(self,token,line=False,prompt=False):
        token=token.encode();start=self.cursor
        while True:
            data=bytes(self.data[start:]);found=data.find(token)
            if found>=0:
                before=data[:found];after=data[found+len(token):]
                boundary=not before or before.endswith((b'\n',b'\r'))
                if (not line and not prompt) or (boundary and (prompt or after.startswith((b'\r\n',b'\n')))):
                    self.cursor=start+found+len(token);self.actions.append(dict(event='observed',token=token.decode(),offset=self.cursor));return
                if line and boundary and after in (b'',b'\r'):pass
                else:start+=found+len(token)
            need(not self.closed,'PTY ended before expected observation')
            self.pump()

    def command(self,text,marker,prompt):
        self.send(text.encode()+b'\n','literal-command');self.expect(marker,line=True);self.expect(prompt,prompt=True)

    def interrupt(self,text,marker,prompt):
        self.send(text.encode()+b'\n','foreground-command');self.expect(marker,line=True)
        foreground=os.tcgetpgrp(self.master)
        need(foreground!=self.sid and foreground in members(self.sid),'actual owned foreground child before Ctrl-C')
        self.actions.append(dict(event='foreground-observed',pgid=foreground))
        self.send(b'\x03','terminal-Ctrl-C');self.expect(prompt,prompt=True)
        until=time.monotonic()+1
        while foreground in members(self.sid) and time.monotonic()<until:time.sleep(.01)
        need(foreground not in members(self.sid),'Ctrl-C foreground child not retired')
        self.actions.append(dict(event='foreground-retired',pgid=foreground))

    def eof(self):
        self.send(b'\x04','terminal-EOF')
        while not self.closed:self.pump()
        self.process.wait(timeout=max(.01,self.deadline-time.monotonic()))
        need(self.process.returncode==0,'natural EOF shell exit must be zero')
        self.record['natural_eof']=True

    def finish(self,success):
        with self.signals.defer_cancellation() as cancelled:
            cleanup_error=None
            missing_eof=success and not self.record.get('natural_eof',False)
            try:
                if self.process is not None:
                    sid=self.process.pid
                    # Retire children while their owning shell can still reap them.
                    for pid,(_,start) in members(sid).items():
                        if pid==sid:continue
                        try:
                            fd=os.pidfd_open(pid)
                            try:
                                if members(sid).get(pid,(None,None))[1]==start:signal.pidfd_send_signal(fd,signal.SIGKILL)
                            finally:os.close(fd)
                        except ProcessLookupError:pass
                    until=time.monotonic()+.8
                    while any(p!=sid for p in members(sid)) and time.monotonic()<until:time.sleep(.01)
                    if self.process.poll() is None:
                        os.killpg(sid,signal.SIGKILL)
                    self.process.wait(timeout=1)
                    first=members(sid);time.sleep(.02);second=members(sid)
                    need(not first and not second,'owned PTY session not EMPTY_TWICE')
                    self.record.update(returncode=self.process.returncode,cleanup='REAPED_EMPTY_TWICE')
            except BaseException as error:
                cleanup_error=type(error).__name__+': '+str(error)
            finally:
                if self.selector is not None:self.selector.close()
                for name in ('master','slave'):
                    fd=getattr(self,name)
                    if fd is not None:os.close(fd);setattr(self,name,None)
                self.record.update(status='PASS' if success and not missing_eof and cleanup_error is None and not cancelled else 'FAIL',bytes=len(self.data),cleanup_error=cleanup_error,cancelled=bool(cancelled))
                (self.out/(self.label+'.pty')).write_bytes(self.data)
                (self.out/(self.label+'.json')).write_text(json.dumps(self.record,sort_keys=True,indent=2)+'\n')
            need(cleanup_error is None,'PTY cleanup failed; preserve private workspace')
            need(not cancelled,'cancelled during PTY cleanup')
            need(not missing_eof,'successful PTY session requires natural EOF')

    def __exit__(self,kind,error,tb):
        if error is not None:self.record['error']=type(error).__name__+': '+str(error)
        self.finish(kind is None)


def capture(argv,env,cwd,signals,seconds=10,limit=65536):
    """Bound the few fixed intake/namespace commands, including failure cleanup."""
    process=None;streams={};data=[bytearray(),bytearray()];error=None
    try:
        with signals.spawn_signals() as restore:
            process=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=restore)
        selector=selectors.DefaultSelector()
        for index,stream in enumerate((process.stdout,process.stderr)):
            selector.register(stream,selectors.EVENT_READ,index);streams[stream]=index
        deadline=time.monotonic()+seconds
        while streams:
            need(time.monotonic()<deadline,'capture deadline')
            for key,_ in selector.select(.03):
                raw=os.read(key.fileobj.fileno(),min(8192,limit-sum(map(len,data))+1))
                if not raw:selector.unregister(key.fileobj);streams.pop(key.fileobj);continue
                need(sum(map(len,data))+len(raw)<=limit,'capture output cap');data[key.data].extend(raw)
        process.wait(timeout=max(.01,deadline-time.monotonic()))
        need(process.returncode==0,'captured command exit '+str(process.returncode)+': '+bytes(data[1])[:300].decode(errors='replace'))
        return bytes(data[0]),bytes(data[1])
    except BaseException as error:
        error.pty_capture_stdout=bytes(data[0]);error.pty_capture_stderr=bytes(data[1]);raise
    finally:
        with signals.defer_cancellation() as cancelled:
            if process is not None:
                if process.poll() is None:
                    try:os.killpg(process.pid,signal.SIGTERM)
                    except ProcessLookupError:pass
                    try:process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        process.wait(timeout=1)
                process.stdout.close();process.stderr.close()
            if 'selector' in locals():selector.close()
            need(not cancelled,'cancelled during capture cleanup')
