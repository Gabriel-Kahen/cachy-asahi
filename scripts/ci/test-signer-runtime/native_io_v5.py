# SPDX-License-Identifier: MIT
"""Native adapter successor: retain actual original task/helper observations.

Root must admit its exact Source and actual hosted-kernel receive proof before
constructing NativeIO. No JSON flag issues that authority. Native syscalls occur
only inside explicitly dispatched methods; the pure controller never calls them.
"""
import struct

RECV, SEND, VALID = 0xc0502100, 0xc0182101, 0x40082102
CONTINUE = 1


class Refused(ValueError):
    pass


class IdleExpired(Refused):
    """No event or receive operation was admitted during this idle wait."""
    pass


class Cancelled(Exception):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def notification(raw):
    need(type(raw) is bytes and len(raw) == 80, 'notification-size')
    identifier,pid,flags,nr,arch,ip,*args = struct.unpack('<QIIiIQ6Q',raw)
    need(identifier > 0 and pid > 0 and flags == 0, 'notification-shape')
    return dict(id=identifier,tid=pid,flags=flags,nr=nr,arch=arch,args=tuple(args))


def proc_row(stat_raw,status_raw,cmdline_raw=None):
    """Pure parser; incomplete proc observations always refuse."""
    need(type(stat_raw) is bytes and len(stat_raw)<=4096 and type(status_raw) is bytes
         and len(status_raw)<=65536, 'proc-bound')
    prefix,rest=stat_raw.decode('ascii').rsplit(')',1)
    pid=int(prefix.split('(',1)[0]);fields=rest.split()
    need(len(fields)>=20,'proc-stat')
    status={}
    for line in status_raw.decode('ascii').splitlines():
        if ':' not in line:continue
        name,value=line.split(':',1)
        need(name not in status,'duplicate-proc-field');status[name]=value.split()
    required={'Pid','Tgid','Uid','Gid','TracerPid','Seccomp','Seccomp_filters'}
    need(required<=set(status),'proc-status-fields')
    one=lambda name:int(status[name][0]) if len(status[name])==1 else None
    uid,gid=tuple(map(int,status['Uid'])),tuple(map(int,status['Gid']))
    need(pid>0 and one('Pid')==pid and len(uid)==len(gid)==4,'proc-credentials')
    row=dict(pid=pid,start=int(fields[19]),ppid=int(fields[1]),group=int(fields[2]),session=int(fields[3]),
             state=fields[0],tgid=one('Tgid'),uid=uid,gid=gid,tracer_pid=one('TracerPid'),
             seccomp_mode=one('Seccomp'),seccomp_filters=one('Seccomp_filters'))
    need(all(type(row[k]) is int and row[k]>=0 for k in ('start','ppid','group','session','tgid','tracer_pid','seccomp_mode','seccomp_filters')),'proc-numeric')
    if cmdline_raw is not None:
        need(type(cmdline_raw) is bytes and 0<len(cmdline_raw)<=65536 and cmdline_raw.endswith(b'\0'),'cmdline-observed')
        row['argv']=tuple(p.decode('utf-8') for p in cmdline_raw[:-1].split(b'\0'))
        need(row['argv'] and all(row['argv']),'cmdline-empty')
    return row


class HeldFD:
    """Private owner wrapper; never transfer this object or serialize its fd."""
    def __init__(self,fd,owner,generation,kind):
        need(type(fd) is int and fd>=0 and type(owner) is object,'fd-owner')
        self.fd,self.owner,self.generation,self.kind=fd,owner,generation,kind
        self.token,self.closed=object(),False


class NativeIO:
    def __init__(self,*,root_admission,expected_root_admission,generation,cancelled,receive_kernel_review):
        need(type(root_admission) is object and root_admission is expected_root_admission,
             'opaque-root-admission-required')
        need(type(receive_kernel_review) is object,'opaque-host-kernel-review-required')
        # This constructor itself is a native dispatch boundary. Never run in inert tests.
        import fcntl,os,select,socket,time,threading
        self.fcntl,self.os,self.select,self.socket,self.time=fcntl,os,select,socket,time
        self.lock=threading.RLock();self.owner=root_admission;self.generation=generation
        self.cancelled=cancelled;self.receive_kernel_review=receive_kernel_review
        self.close_uncertain=False;self.receive_active=False;self.diagnostic=None
        self.original_pidfd=None
        self.helper_attempted=False;self.helper_task_absent=False
        self.agent_attempted=False
        self.running=None;self.control=None;self.control_retired=False;self.listener=None
        self.control_identity=None

    def live(self,end,*,cleanup=False):
        now=self.time.monotonic()
        need(type(end) in (int,float) and now<end,'native-original-deadline')
        if not cleanup and self.cancelled():raise Cancelled()
        return now

    def held(self,h,kind=None):
        need(type(h) is HeldFD and h.owner is self.owner and h.generation==self.generation
             and not h.closed and (kind is None or h.kind==kind),'native-fd-custody')
        return h.fd

    def receive(self,listener,end,*,idle=False):
        with self.lock:
            need(type(idle) is bool,'receive-idle-option')
            need(not self.receive_active,'overlapping-receive-refused')
            self.receive_active=True
            try:return self._receive_locked(listener,end,idle=idle)
            finally:self.receive_active=False

    def _receive_locked(self,listener,end,*,idle=False):
        """Lock covers fresh poll/token consumption/close; one receiver, no ADDFD.

        The reviewed kernel counter proof makes RECV non-waiting-for-future-event
        after EPOLLIN even on task death. This is not a hard real-time guarantee.
        """
        with self.lock:
            need(type(idle) is bool,'receive-idle-option')
            fd=self.held(listener,'listener');poll=self.select.poll()
            poll.register(fd,self.select.POLLIN|self.select.POLLERR|self.select.POLLHUP)
            idle_only=idle
            def wait_live():
                try:return self.live(end)
                except Refused as error:
                    if idle_only and type(error) is Refused and error.args==('native-original-deadline',):
                        if self.cancelled():raise Cancelled()
                        raise IdleExpired('native-original-idle-deadline') from error
                    raise
            while True:
                now=wait_live()
                events=poll.poll(max(1,min(50,int((end-now)*1000))))
                # Any readiness permanently excludes ordinary idle completion in
                # this invocation, including vanished/interrupted requests.
                if events:idle_only=False
                wait_live()
                if not events:continue
                need(len(events)==1 and events[0][0]==fd and events[0][1]&self.select.POLLIN
                     and not events[0][1]&(self.select.POLLERR|self.select.POLLHUP),'fresh-listener-EPOLLIN-required')
                raw=bytearray(80)
                try:self.fcntl.ioctl(fd,RECV,raw,True)
                except OSError as error:
                    if error.errno in (2,4):continue # interrupted/dead request; fresh poll again
                    raise
                self.live(end)
                return notification(bytes(raw))

    def valid(self,listener,identifier):
        with self.lock:
            fd=self.held(listener,'listener')
            need(type(identifier) is int and 0<identifier<2**64,'notification-id')
            try:self.fcntl.ioctl(fd,VALID,struct.pack('<Q',identifier))
            except OSError as error:
                if error.errno==2:return False
                raise
            return True

    def birth(self,listener,n,running,end):
        """No poll/wait/reaper before both checks. A bad postcheck never signals."""
        with self.lock:
            self.live(end);need(n['tid']==running.pid,'owned-Popen-birth')
            need(self.original_pidfd is None,'original-birth-already-owned')
            need(self.valid(listener,n['id']),'birth-precheck')
            fd=self.os.pidfd_open(running.pid,0)
            try:
                need(self.valid(listener,n['id']),'birth-postcheck')
                self.live(end)
            except BaseException:
                try:self.os.close(fd)
                except BaseException:self.close_uncertain=True
                raise
            self.original_pidfd=HeldFD(fd,self.owner,self.generation,'pidfd')
            return self.original_pidfd

    def send(self,listener,identifier,*,proceed,error=0,end,cleanup=False):
        with self.lock:
            self.live(end,cleanup=cleanup);fd=self.held(listener,'listener')
            need(type(proceed) is bool and type(error) is int and -4095<=error<=0
                 and (not proceed or error==0),'closed-response')
            need(self.valid(listener,identifier),'send-id-current')
            self.fcntl.ioctl(fd,SEND,struct.pack('<QqiI',identifier,0,error,CONTINUE if proceed else 0))
            self.live(end,cleanup=cleanup)

    def terminated_events(self,fd,events):
        if not events:return False
        need(len(events)==1 and events[0][0]==fd,'pidfd-event-owner')
        flags=events[0][1]
        allowed=self.select.POLLIN|self.select.POLLHUP
        need(type(flags) is int and flags!=0 and flags & ~allowed == 0,'pidfd-event-uncertain')
        return True

    def live_pidfd(self,pidfd):
        with self.lock:
            fd=self.held(pidfd,'pidfd');poll=self.select.poll()
            poll.register(fd,self.select.POLLIN|self.select.POLLHUP|self.select.POLLERR)
            return not self.terminated_events(fd,poll.poll(0))

    def read_proc(self,pid,end,*,command_line=False,cleanup=False):
        need(type(pid) is int and pid>0,'owned-proc-PID')
        def read(name,cap):
            self.live(end,cleanup=cleanup)
            fd=self.os.open('/proc/'+str(pid)+'/'+name,self.os.O_RDONLY|self.os.O_NOFOLLOW|self.os.O_NONBLOCK)
            try:
                chunks=[];size=0
                while True:
                    self.live(end,cleanup=cleanup);block=self.os.read(fd,min(4096,cap+1-size))
                    if not block:break
                    chunks.append(block);size+=len(block);need(size<=cap,'proc-read-bound')
                return b''.join(chunks)
            finally:self.os.close(fd)
        raw=read('stat',4096);status=read('status',65536)
        cmd=read('cmdline',65536) if command_line else None
        return proc_row(raw,status,cmd)

    def bracket(self,pidfd,pid,end,*,listener=None,identifier=None,cleanup=False):
        """All group/thread proc reads are between fresh checks of ORIGINAL pidfd."""
        with self.lock:
            self.live(end,cleanup=cleanup)
            valid_before=listener is None or self.valid(listener,identifier)
            need(valid_before,'observation-pre-ID')
            before=self.live_pidfd(pidfd);need(before,'original-task-dead-before-proc')
            row=self.read_proc(pid,end,command_line=True,cleanup=cleanup)
            after=self.live_pidfd(pidfd);need(after,'original-task-dead-after-proc')
            valid_after=listener is None or self.valid(listener,identifier)
            need(valid_after,'observation-post-ID')
            self.live(end,cleanup=cleanup)
            return row,dict(valid_before=valid_before,valid_after=valid_after,
                            pidfd_unreadable_before=before,pidfd_unreadable_after=after)

    def close(self,h):
        with self.lock:
            need(not self.receive_active,'close-during-receive-refused')
            fd=self.held(h)
            # Linux close errors never justify retrying an fd number that may be reused.
            h.closed=True
            try:self.os.close(fd)
            except BaseException:
                self.close_uncertain=True;raise

    def terminate(self,pidfd,end):
        """Caller MUST validate a fresh typed image/argv/custody proof first."""
        import signal
        with self.lock:
            fd=self.held(pidfd,'pidfd')
            for signum in (signal.SIGTERM,signal.SIGKILL):
                self.live(end,cleanup=True)
                if not self.live_pidfd(pidfd):return True
                signal.pidfd_send_signal(fd,signum)
                poll=self.select.poll();poll.register(fd,self.select.POLLIN|self.select.POLLHUP|self.select.POLLERR)
                now=self.time.monotonic();wait_end=min(end,now+2)
                while self.time.monotonic()<wait_end:
                    self.live(end,cleanup=True)
                    if self.terminated_events(fd,poll.poll(50)):return True
            return not self.live_pidfd(pidfd)


def receive_handoff(io,channel,*,nonce,owned_pid,uid,gid,end):
    """Kernel credentials, not socketpair-creation peer credentials."""
    sock=io.socket;fds=[]
    with io.lock:
        channel.setblocking(False)
        poll=io.select.poll();poll.register(channel.fileno(),io.select.POLLIN|io.select.POLLERR|io.select.POLLHUP)
        while True:
            now=io.live(end)
            if not poll.poll(max(1,min(50,int((end-now)*1000)))):continue
            try:payload,ancillary,flags,_=channel.recvmsg(41,sock.CMSG_SPACE(4)+sock.CMSG_SPACE(12),sock.MSG_CMSG_CLOEXEC)
            except BlockingIOError:continue
            break
        try:
            # recvmsg already installed rights descriptors. Collect ALL before any refusal.
            for level,kind,raw in ancillary:
                if level==sock.SOL_SOCKET and kind==sock.SCM_RIGHTS:
                    count=len(raw)//4
                    if count:fds.extend(struct.unpack('<'+'i'*count,raw[:4*count]))
            creds=[]
            for level,kind,raw in ancillary:
                need(level==sock.SOL_SOCKET,'ancillary-level')
                if kind==sock.SCM_RIGHTS:
                    need(len(raw)%4==0,'rights-size')
                elif kind==sock.SCM_CREDENTIALS:
                    need(len(raw)==12,'credential-size');creds.append(struct.unpack('<iii',raw))
                else:raise Refused('unexpected-ancillary')
            returned_flags=flags & ~sock.MSG_CMSG_CLOEXEC
            if returned_flags==0 and len(payload)==40 and not fds and creds==[(owned_pid,uid,gid)] and payload[:32]==nonce.encode('ascii'):
                stage,code=struct.unpack('<ii',payload[32:])
                need(stage in (1,2) and 1<=code<=4095,'shim-diagnostic-shape')
                io.diagnostic=dict(stage='install' if stage==1 else 'initial-exec',errno=code)
                raise Refused('shim-operation-failed')
            need(returned_flags==0 and payload==nonce.encode('ascii') and len(payload)==32 and len(fds)==1
                 and creds==[(owned_pid,uid,gid)],'listener-handoff-custody')
            io.live(end)
            fd=fds.pop();return HeldFD(fd,io.owner,io.generation,'listener')
        finally:
            for fd in set(fds):
                try:io.os.close(fd)
                except BaseException:io.close_uncertain=True
