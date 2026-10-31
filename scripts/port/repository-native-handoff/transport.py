#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned local Docker transport. Construction never contacts the daemon.

Real actors require explicit CLI, endpoint, environment and create grants.
The shared pipe supervisor is also exercised by clearly labeled Python fixtures.
"""
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import threading
import time

SIGNALS = {signal.SIGINT, signal.SIGTERM}
ENV_KEYS = {'PATH', 'HOME', 'DOCKER_CONFIG', 'DOCKER_HOST', 'DOCKER_BUILDKIT', 'LC_ALL', 'TMPDIR'}
CLI = Path('/usr/bin/docker')
ENDPOINT = Path('/run/docker.sock')
MAX_BYTES = 64 * 1024**2
CAPS = ('CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID','SYS_CHROOT')


class Refused(ValueError):
    pass


class Cancelled(KeyboardInterrupt):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def alive(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline,
         'finite unexpired transport deadline required')


def identity(info):
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


@contextmanager
def directory(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'parent traversal refused')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    seen = [(Path('/'), identity(os.fstat(fd)))]
    try:
        current = Path('/')
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new; current /= part
            seen.append((current, identity(os.fstat(fd))))
        yield fd
        need(all(identity(path.lstat()) == before for path, before in seen), 'ancestor identity drift')
    finally:
        os.close(fd)


def read_file(path, limit=128 * 1024**2, *, hold=False):
    path = Path(path).absolute()
    fd = None
    try:
        with directory(path.parent) as parent:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
                 'bounded regular single-link input required')
            sha = hashlib.sha256(); size = 0; data = bytearray() if limit <= 4096 else None
            while chunk := os.read(fd, 65536):
                size += len(chunk); need(size <= limit, 'input byte bound'); sha.update(chunk)
                if data is not None: data.extend(chunk)
            after = os.fstat(fd); live = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(size == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(live, key)
                                                for key in fields), 'input identity drift')
            value = {'sha256': sha.hexdigest(), 'identity': identity(before), 'size': size,
                     'data': bytes(data) if data is not None else None}
        if hold:
            value['fd'] = fd; fd = None
        return value
    finally:
        if fd is not None: os.close(fd)


class Events:
    def __init__(self):
        self.cancelled = False
        self.deferring = False
        self.numbers = set()

    def handler(self, number, frame):
        self.cancelled = True
        self.numbers.add(number)
        if not self.deferring: raise Cancelled('transport cancelled')


@contextmanager
def handlers(events):
    need(threading.current_thread() is threading.main_thread(), 'main-thread transport required')
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    original = {number: signal.getsignal(number) for number in SIGNALS}
    first_error = None
    try:
        for number in SIGNALS: signal.signal(number, events.handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield mask
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        for number, handler in original.items():
            for _ in range(2):
                try: signal.signal(number, handler)
                except BaseException as error: first_error = first_error or error
                if signal.getsignal(number) == handler: break
        pending = signal.sigpending() & (SIGNALS - set(mask))
        while pending:
            events.numbers.add(signal.sigwait(pending)); events.cancelled = True
            pending = signal.sigpending() & (SIGNALS - set(mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        # Nested owning launch/supervisor handlers must learn that cancellation
        # occurred; otherwise they could continue unrelated legacy stages.
        for number in events.numbers:
            if callable(original[number]):
                try: original[number](number, None)
                except BaseException as error: first_error = first_error or error
        if first_error: raise first_error
        if events.cancelled: raise Cancelled('transport cancelled after teardown')


def exited(process):
    """Observe natural exit without releasing PID ownership before group disposal."""
    row = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if row is None: return None
    return row.si_status if row.si_code == os.CLD_EXITED else -row.si_status


def group_signal(pid, number):
    try: os.killpg(pid, number)
    except ProcessLookupError: pass


def supervise(argv, *, env, deadline, limit, on_stdout=None, on_stdin=None, pass_fds=(), preflight=None):
    """Finite duplex child supervision; forced teardown never reports exit zero.

    No shell is used. argv is already authorized by the caller. This function
    records direct-child reaping and group disposal separately from daemon facts.
    """
    alive(deadline)
    need(type(limit) is int and 0 < limit <= MAX_BYTES, 'finite pipe byte bound required')
    need(on_stdin is None or callable(on_stdout) and callable(on_stdin), 'duplex callbacks required')
    events = Events(); process = None; streams = []; output = [bytearray(), bytearray()]
    forced = False; natural = None; teardown = None; fault = None; stdin_bytes = 0; writes = 0
    observation = {'execution': 'bounded-local-child', 'pid': None, 'natural_returncode': None,
                   'teardown_returncode': None, 'forced_teardown': False, 'direct_child_reaped': False,
                   'group_disposal_requested': False, 'stdin_bytes': 0, 'stdin_writes': 0, 'cancelled': False}
    try:
        with handlers(events) as original_mask:
            try:
                if preflight: preflight()
                alive(deadline)
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                try:
                    process = subprocess.Popen(argv, stdin=subprocess.PIPE if on_stdin else subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True,
                        pass_fds=pass_fds, preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, original_mask))
                    observation['pid'] = process.pid
                    streams = [stream for stream in (process.stdin, process.stdout, process.stderr) if stream is not None]
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                for stream in streams: os.set_blocking(stream.fileno(), False)
                queue = bytearray(); ack_count = 0; stdin_registered = False; stdin_closed = False; read_open = 2
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 0)
                    selector.register(process.stderr, selectors.EVENT_READ, 1)
                    while read_open:
                        alive(deadline)
                        if events.cancelled: raise Cancelled('sticky transport cancellation')
                        if on_stdin and not stdin_closed:
                            message = on_stdin()
                            if message is not None:
                                need(isinstance(message, bytes) and 0 < len(message) <= 65536 and ack_count < 2,
                                     'finite typed ACK required')
                                ack_count += 1; queue.extend(message)
                            if queue and not stdin_registered:
                                selector.register(process.stdin, selectors.EVENT_WRITE, 2); stdin_registered = True
                        if natural is None:
                            natural = exited(process)
                            if natural is not None:
                                need(not queue, 'producer exited before queued ACK delivery')
                                group_signal(process.pid, signal.SIGKILL)
                                observation['group_disposal_requested'] = True
                        for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                            if key.data == 2:
                                try: count = os.write(key.fd, queue)
                                except BlockingIOError: continue
                                except BrokenPipeError as error: raise Refused('producer stdin closed before ACK') from error
                                need(count > 0, 'zero ACK write'); del queue[:count]
                                stdin_bytes += count; writes += 1
                                if not queue:
                                    selector.unregister(process.stdin); stdin_registered = False
                            else:
                                try: chunk = os.read(key.fd, min(65536, limit+1-len(output[0])-len(output[1])))
                                except BlockingIOError: continue
                                if not chunk:
                                    selector.unregister(key.fileobj); read_open -= 1
                                else:
                                    output[key.data].extend(chunk)
                                    need(len(output[0])+len(output[1]) <= limit, 'child output byte bound')
                                    if key.data == 0 and on_stdout: on_stdout(chunk)
                        alive(deadline)
                    need(not queue, 'EOF before ACK delivery')
                    if natural is None:
                        while natural is None:
                            alive(deadline); time.sleep(min(.01, max(0, deadline-time.monotonic())))
                            natural = exited(process)
                    alive(deadline)
            except BaseException as error:
                fault = error
            finally:
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS); events.deferring = True
                try:
                    try:
                        if process is not None:
                            if natural is None:
                                natural = exited(process)
                            forced = fault is not None or natural is None
                            group_signal(process.pid, signal.SIGTERM if forced else signal.SIGKILL)
                            observation['group_disposal_requested'] = True
                            # Cooperative children may reap their own descendants.
                            end = time.monotonic()+.2
                            while exited(process) is None and time.monotonic()<end: time.sleep(.005)
                            group_signal(process.pid, signal.SIGKILL)
                            teardown = process.wait(timeout=2)
                            observation['direct_child_reaped'] = True
                    finally:
                        first_close_error = None
                        for stream in streams:
                            try: stream.close()
                            except BaseException as error: first_close_error = first_close_error or error
                        if first_close_error: raise first_close_error
                finally:
                    events.deferring = False
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    except BaseException as error:
        fault = fault or error
    observation.update(natural_returncode=natural, teardown_returncode=teardown, forced_teardown=forced,
                       stdin_bytes=stdin_bytes, stdin_writes=writes, cancelled=events.cancelled)
    code = natural if natural is not None and not forced and not events.cancelled and fault is None else (
        teardown if teardown is not None and teardown != 0 else -1)
    result = {'exit_code': code, 'stdout': bytes(output[0]), 'stderr': bytes(output[1])}
    if preflight:
        try: preflight()
        except BaseException as error: fault = fault or error
    if fault is not None:
        if result['exit_code'] == 0: result['exit_code'] = -1
        error = Refused('child supervision refused'); error.result = result; error.observation = observation
        raise error from fault
    return result, observation


class DockerTransport:
    """Fixed local endpoint and pinned CLI; no Docker calls in __init__/bind."""
    def __init__(self, *, cli_sha256, endpoint_identity, env, create_validator, identity_guard=None):
        need(isinstance(cli_sha256, str) and re.fullmatch('[0-9a-f]{64}', cli_sha256), 'external Docker CLI pin required')
        need(isinstance(env, dict) and set(env) <= ENV_KEYS and all(isinstance(k, str) and isinstance(v, str)
             and '\0' not in v for k, v in env.items()), 'explicit allowlisted environment required')
        need(env.get('PATH') == '/usr/bin:/bin' and env.get('DOCKER_HOST') == 'unix:///run/docker.sock'
             and env.get('DOCKER_BUILDKIT') == '0' and env.get('LC_ALL') == 'C', 'fixed local Docker environment required')
        need(callable(create_validator) and (identity_guard is None or callable(identity_guard)), 'registered create/source guard required')
        self.fd = None
        try:
            mask=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
            try:
                self.cli=read_file(CLI,hold=True);self.fd=self.cli['fd']
            finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)
            need(self.cli['sha256'] == cli_sha256 and self.cli['identity'][3] == 0
                 and stat.S_IMODE(self.cli['identity'][2]) == 0o755, 'Docker CLI bytes/owner/mode differ')
            need(isinstance(endpoint_identity, (tuple, list)) and len(endpoint_identity) == 6,
                 'externally observed endpoint identity required')
            self.endpoint = tuple(endpoint_identity); self.env = dict(env)
            self.validator, self.guard = create_validator, identity_guard
            for key in ('HOME', 'DOCKER_CONFIG', 'TMPDIR'):
                need(key in env, 'private tool-state directory required')
                with directory(env[key]) as parent:
                    info = os.fstat(parent)
                    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                         'owned private tool-state mode required')
                    need(not os.listdir(parent), 'empty private tool-state required')
            self.private_dirs = {env[key]:identity(Path(env[key]).lstat()) for key in ('HOME','DOCKER_CONFIG','TMPDIR')}
            self.scope = None; self.cid = None; self.created = False; self.cancelled = False; self.records = []
            self._preflight()
        except BaseException:
            self.close()
            raise

    def _preflight(self):
        need(self.fd is not None, 'closed transport')
        current = read_file(CLI)
        need(current['sha256'] == self.cli['sha256'] and current['identity'] == self.cli['identity']
             and identity(os.fstat(self.fd)) == self.cli['identity'], 'pinned CLI identity drift')
        with directory(ENDPOINT.parent) as parent:
            info = os.stat(ENDPOINT.name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and identity(info) == self.endpoint,
                 'fixed endpoint socket identity drift')
        for path,before in self.private_dirs.items():
            with directory(path) as parent:
                need(identity(os.fstat(parent))==before,'private tool-state identity drift')
        # These selected builtin operations need no authentication or contexts.
        # A newly injected config/helper must not become a host credential actor.
        with directory(self.env['DOCKER_CONFIG']) as parent:
            need(not os.listdir(parent),'unexpected Docker configuration/helper input')
        if self.guard: self.guard()

    def bind(self, name, image_id):
        need(self.scope is None and isinstance(name,str) and isinstance(image_id,str)
             and re.fullmatch('cachy-asahi-repository-[0-9a-f]{32}', name)
             and re.fullmatch('sha256:[0-9a-f]{64}', image_id), 'one exact repository scope required')
        self.scope = {'name': name, 'image_id': image_id}; return self

    def _authorize(self, argv, attach=False):
        need(self.scope is not None and isinstance(argv, (list, tuple)) and all(isinstance(x, str) for x in argv)
             and argv and argv[0] == 'docker', 'bound typed Docker command required')
        name, image = self.scope['name'], self.scope['image_id']
        allowed = [(['docker', 'image', 'inspect', image], False), (['docker','info','--format','{{.Architecture}}'],False),
            (['docker','container','ls','-a','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'],False)]
        if self.created:
            allowed += [(['docker','container','inspect',name],False),
                        (['docker','container','ls','-a','--no-trunc','--format','{{.ID}} {{.Names}}'],False)]
        if self.cid:
            allowed += [(['docker','container','inspect',self.cid],False),
                        (['docker','container','rm','-f',self.cid],False)]
            if not self.cancelled: allowed += [(['docker','start','--attach','--interactive',self.cid],True)]
        if any(list(argv)==command and attach is channel for command,channel in allowed): return
        need(not attach and list(argv[:3])==['docker','create','-i'] and not self.created and not self.cancelled,
             'unsupported Docker operation')
        approved = self.validator(list(argv))
        need(isinstance(approved, dict) and set(approved)=={'name','image_id','cidfile'}
             and approved['name']==name and approved['image_id']==image
             and isinstance(approved['cidfile'], (str,Path)), 'registered literal create validation required')
        path = Path(approved['cidfile']).absolute()
        need(argv[3:5]==['--cidfile',str(path)] and path.name=='cid' and path.parent.name=='launch-'+name.removeprefix('cachy-asahi-repository-'),
             'private creation CID path differs')
        self._literal_create(argv,path)
        with directory(path.parent) as parent:
            info=os.fstat(parent)
            need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700,'owned private CID directory required')
        need(not path.exists() and not path.is_symlink(), 'fresh CID file required')
        self.scope['cidfile'] = path; self.created = True

    def _literal_create(self,argv,cidfile):
        name,image=self.scope['name'],self.scope['image_id'];nonce=name.removeprefix('cachy-asahi-repository-')
        prefix=['docker','create','-i','--cidfile',str(cidfile),'--name',name,'--pull=never','--platform=linux/arm64',
            '--user','0:0','--network=none','--cgroupns=private','--cap-drop=ALL','--security-opt=no-new-privileges',
            '--pids-limit=512','--memory=8g','--cpus=4']+['--cap-add='+cap for cap in CAPS]+[
            '--read-only','--tmpfs','/scratch:rw,nosuid,nodev,exec,size=6g,mode=0700',
            '--tmpfs','/test-home:rw,nosuid,nodev,exec,size=128m,mode=0700']
        need(list(argv[:len(prefix)])==prefix,'literal root-wrapper create policy differs')
        position=len(prefix)
        for dest,ro in (('/inputs',True),('/runner',True),('/out',False)):
            need(len(argv)>position+1 and argv[position]=='--mount','literal create mounts differ')
            value=argv[position+1];suffix=',dst='+dest+(',readonly'if ro else'')
            need(value.startswith('type=bind,src=')and value.endswith(suffix),'literal bind differs')
            source=value[len('type=bind,src='):-len(suffix)]
            need(Path(source).is_absolute()and '..'not in Path(source).parts and not re.search('[,\n\r\x00]',source),
                 'canonical literal bind required')
            position+=2
        tail=['--env','CACHY_ASAHI_REPOSITORY_CONTAINER=1','--env','CACHY_ASAHI_DISPOSABLE_REPOSITORY='+nonce,
            '--env','CACHY_ASAHI_IMAGE_ID='+image,'--entrypoint=/usr/bin/python3',image,'-B','-I','/runner/producer.py',
            '--handoff-deadline']
        need(list(argv[position:position+len(tail)])==tail,'literal wrapper environment/entry differs')
        position+=len(tail)
        need(len(argv)==position+6,'literal wrapper suffix differs')
        cutoff=float(argv[position]);alive(cutoff)
        need(list(argv[position+1:position+4])==['--inputs','/inputs/manifest.json','--inputs-sha256']
             and re.fullmatch('[0-9a-f]{64}',argv[position+4])
             and argv[position+5]=='--allow-disposable-repository-test','literal original producer inputs differ')

    def _invoke(self, argv, *, deadline, limit, on_stdout=None, on_stdin=None):
        attach = on_stdin is not None
        alive(deadline);self._preflight();self._authorize(argv, attach);alive(deadline)
        result = observation = None
        try:
            result, observation = supervise(['/proc/self/fd/'+str(self.fd), *argv[1:]], env=self.env,
                deadline=deadline,limit=limit,on_stdout=on_stdout,on_stdin=on_stdin,pass_fds=(self.fd,),preflight=self._preflight)
            return result
        except Refused as error:
            result = getattr(error,'result',None); observation = getattr(error,'observation',None)
            self.cancelled = self.cancelled or bool(observation and observation['cancelled'])
            raise
        finally:
            if self.created and self.cid is None:
                try:
                    record=read_file(self.scope['cidfile'],128);raw=record['data'].decode()
                    cid=raw.removesuffix('\n')
                    need(re.fullmatch('[0-9a-f]{64}',cid) and raw in (cid,cid+'\n')
                         and record['identity'][3]==os.getuid() and not stat.S_IMODE(record['identity'][2])&0o022,
                         'full private Docker CID required'); self.cid=cid
                except (OSError,ValueError): pass
            if result is not None:
                self.records.append({'argv':list(argv),'result':result,'observation':observation,
                                     'cli_sha256':self.cli['sha256'],'endpoint_identity':self.endpoint,
                                     'execution':'local-pinned-Docker-child'})

    def run(self, argv, *, deadline, limit):
        return self._invoke(argv,deadline=deadline,limit=limit)

    def attach(self, argv, *, on_stdout, on_stdin, deadline, limit):
        need(callable(on_stdout) and callable(on_stdin), 'explicit duplex callbacks required')
        return self._invoke(argv,deadline=deadline,limit=limit,on_stdout=on_stdout,on_stdin=on_stdin)

    def close(self):
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
        try:
            if self.fd is not None:
                fd=self.fd;self.fd=None;os.close(fd)
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,mask)


# Root-selected prep route only. Retain unknown/foreign stream objects and
# unreaped Popen objects until this one-shot interpreter exits. This is local
# resource custody, not an execution grant or a generic process registry.
PREP_QUARANTINE=[]

@contextmanager
def prep_handlers(events,cleanup_end):
    """Original selected handlers, finite pending drain and sticky first faults."""
    need(threading.current_thread() is threading.main_thread(),'main-thread transport required')
    mask=None;original={};first=None;uncertain=False;setup_started=False
    try:
        setup_started=True;mask=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
        for number in SIGNALS:original[number]=signal.getsignal(number)
        for number in SIGNALS:signal.signal(number,events.handler)
        signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        yield mask
    except BaseException as error:
        first=error;events.cancelled |= isinstance(error,KeyboardInterrupt)
        if setup_started and mask is None:uncertain=True
    finally:
        def retain(error):
            nonlocal first,uncertain
            uncertain=True;events.cancelled |= isinstance(error,KeyboardInterrupt)
            if first is None:first=error
        try:signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
        except BaseException as error:retain(error)
        for number,handler in original.items():
            try:signal.signal(number,handler)
            except BaseException as error:retain(error)
        try:
            need(mask is not None,'preparation signal-mask custody')
            pending=signal.sigpending() & (SIGNALS-set(mask));count=0
            while pending:
                alive(cleanup_end);need(count<4,'preparation pending-signal bound');count+=1
                events.numbers.add(signal.sigwait(pending));events.cancelled=True
                pending=signal.sigpending() & (SIGNALS-set(mask))
        except BaseException as error:retain(error)
        try:
            need(mask is not None,'preparation signal-mask custody')
            signal.pthread_sigmask(signal.SIG_SETMASK,mask)
        except BaseException as error:retain(error)
        for number in events.numbers:
            if callable(original[number]):
                try:original[number](number,None)
                except BaseException as error:retain(error)
        try:alive(cleanup_end)
        except BaseException as error:retain(error)
    if first is not None:
        markers=BaseException.__getattribute__(first,'__dict__')
        if type(markers) is dict:
            events.cancelled |= markers.get('native_preflight_cancelled') is True
            uncertain |= markers.get('native_preflight_cleanup_uncertain') is True
        BaseException.__setattr__(first,'native_preflight_cancelled',events.cancelled)
        BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',uncertain)
        raise first
    if events.cancelled:raise Cancelled('preparation transport cancelled after teardown')

def prep_supervise(argv, *, env, deadline, cleanup_end, limit, on_stdout=None, on_stdin=None, pass_fds=(), preflight=None):
    """Finite duplex child supervision; forced teardown never reports exit zero.

    No shell is used. argv is already authorized by the caller. This function
    records direct-child reaping and group disposal separately from daemon facts.
    """
    import sys
    module=sys.modules.get(__name__)
    need(module is not None and module.__dict__ is globals(),'preparation module registry required')
    need(sys.modules.get('root_p0_preparation_quarantine') in (None,module),'foreign preparation quarantine registry')
    need(not PREP_QUARANTINE,'preparation quarantine forbids another birth')
    alive(deadline)
    need(type(cleanup_end) in (int,float) and math.isfinite(cleanup_end) and deadline < cleanup_end,
         'original preparation work/cleanup endpoints required')
    need(type(limit) is int and 0 < limit <= MAX_BYTES, 'finite pipe byte bound required')
    need(on_stdin is None or callable(on_stdout) and callable(on_stdin), 'duplex callbacks required')
    events = Events(); process = None; streams = []; stream_nodes={}; retired=set(); quarantined=[]; birth_attempted=False; output = [bytearray(), bytearray()]
    cleanup_fault=False
    forced = False; natural = None; teardown = None; fault = None; stdin_bytes = 0; writes = 0
    observation = {'execution': 'bounded-local-child', 'pid': None, 'natural_returncode': None,
                   'teardown_returncode': None, 'forced_teardown': False, 'direct_child_reaped': False,
                   'group_disposal_requested': False, 'stdin_bytes': 0, 'stdin_writes': 0, 'cancelled': False}
    try:
        with prep_handlers(events,cleanup_end) as original_mask:
            try:
                if preflight: preflight()
                alive(deadline)
                blocked = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                try:
                    birth_attempted=True
                    process = subprocess.Popen(argv, stdin=subprocess.PIPE if on_stdin else subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True,
                        pass_fds=pass_fds, preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, original_mask))
                    observation['pid'] = process.pid
                    streams = [stream for stream in (process.stdin, process.stdout, process.stderr) if stream is not None]
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                for stream in streams:
                    stream_nodes[id(stream)]=(stream.fileno(),identity(os.fstat(stream.fileno())))
                    os.set_blocking(stream.fileno(),False)
                queue = bytearray(); ack_count = 0; stdin_registered = False; stdin_closed = False; read_open = 2
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 0)
                    selector.register(process.stderr, selectors.EVENT_READ, 1)
                    while read_open:
                        alive(deadline)
                        if events.cancelled: raise Cancelled('sticky transport cancellation')
                        if on_stdin and not stdin_closed:
                            message = on_stdin()
                            if message is not None:
                                need(isinstance(message, bytes) and 0 < len(message) <= 65536 and ack_count < 2,
                                     'finite typed ACK required')
                                ack_count += 1; queue.extend(message)
                            if queue and not stdin_registered:
                                selector.register(process.stdin, selectors.EVENT_WRITE, 2); stdin_registered = True
                        if natural is None:
                            natural = exited(process)
                            if natural is not None:
                                need(not queue, 'producer exited before queued ACK delivery')
                                alive(cleanup_end)
                                group_signal(process.pid, signal.SIGKILL)
                                observation['group_disposal_requested'] = True
                        for key, _ in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                            if key.data == 2:
                                try: count = os.write(key.fd, queue)
                                except BlockingIOError: continue
                                except BrokenPipeError as error: raise Refused('producer stdin closed before ACK') from error
                                need(count > 0, 'zero ACK write'); del queue[:count]
                                stdin_bytes += count; writes += 1
                                if not queue:
                                    selector.unregister(process.stdin); stdin_registered = False
                            else:
                                try: chunk = os.read(key.fd, min(65536, limit+1-len(output[0])-len(output[1])))
                                except BlockingIOError: continue
                                if not chunk:
                                    selector.unregister(key.fileobj); read_open -= 1
                                else:
                                    output[key.data].extend(chunk)
                                    need(len(output[0])+len(output[1]) <= limit, 'child output byte bound')
                                    if key.data == 0 and on_stdout: on_stdout(chunk)
                        alive(deadline)
                    need(not queue, 'EOF before ACK delivery')
                    if natural is None:
                        while natural is None:
                            alive(deadline); time.sleep(min(.01, max(0, deadline-time.monotonic())))
                            natural = exited(process)
                    alive(deadline)
            except BaseException as error:
                fault = error
                events.cancelled |= isinstance(error,KeyboardInterrupt)
            finally:
                blocked=None;events.deferring=True
                def retain(error):
                    nonlocal fault,cleanup_fault
                    cleanup_fault=True;events.cancelled |= isinstance(error,KeyboardInterrupt)
                    if fault is None:fault=error
                try:
                    try:blocked=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
                    except BaseException as error:retain(error)
                    try:
                        if process is not None:
                            if natural is None:natural=exited(process)
                            forced=fault is not None or natural is None
                            alive(cleanup_end)
                            group_signal(process.pid,signal.SIGTERM if forced else signal.SIGKILL)
                            observation['group_disposal_requested']=True
                            end=min(cleanup_end,time.monotonic()+.2)
                            while exited(process) is None and time.monotonic()<end:
                                alive(cleanup_end);time.sleep(min(.005,cleanup_end-time.monotonic()))
                            alive(cleanup_end);group_signal(process.pid,signal.SIGKILL)
                            alive(cleanup_end);teardown=process.wait(timeout=min(2,cleanup_end-time.monotonic()))
                            observation['direct_child_reaped']=True
                            need(forced or teardown==natural,'preparation natural/reaped status mismatch')
                            alive(cleanup_end)
                    except BaseException as error:retain(error)
                finally:
                    # Each actual stream remains referenced. Unknown/foreign identities
                    # are quarantined, never blindly numeric-closed or GC-released.
                    for stream in streams:
                        try:
                            need(id(stream) not in retired,'preparation stream-close retry')
                            before=stream_nodes.get(id(stream))
                            need(before is not None and stream.fileno()==before[0] and
                                 identity(os.fstat(before[0]))==before[1],'preparation stream custody')
                            retired.add(id(stream));stream.close()
                        except BaseException as error:
                            quarantined.append(stream);retain(error)
                    events.deferring=False
                    if blocked is not None:
                        try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
                        except BaseException as error:retain(error)
    except BaseException as error:
        events.cancelled |= isinstance(error,KeyboardInterrupt)
        cleanup_fault=True
        if fault is None:fault=error
    observation.update(natural_returncode=natural, teardown_returncode=teardown, forced_teardown=forced,
                       stdin_bytes=stdin_bytes, stdin_writes=writes, cancelled=events.cancelled)
    code = natural if natural is not None and not forced and not events.cancelled and fault is None else (
        teardown if teardown is not None and teardown != 0 else -1)
    result = {'exit_code': code, 'stdout': bytes(output[0]), 'stderr': bytes(output[1])}
    if preflight:
        try: preflight()
        except BaseException as error:
            events.cancelled |= isinstance(error,KeyboardInterrupt)
            cleanup_fault=True
            if fault is None:fault=error
    if fault is not None:
        if result['exit_code'] == 0: result['exit_code'] = -1
        markers=BaseException.__getattribute__(fault,'__dict__')
        if type(markers) is dict:
            events.cancelled |= markers.get('native_preflight_cancelled') is True
            cleanup_fault |= markers.get('native_preflight_cleanup_uncertain') is True
        observation['cancelled']=events.cancelled
        if quarantined or birth_attempted and not observation['direct_child_reaped']:
            PREP_QUARANTINE.append((process if not observation['direct_child_reaped'] else None,tuple(quarantined)))
            sys.modules['root_p0_preparation_quarantine']=module
        BaseException.__setattr__(fault,'result',result)
        BaseException.__setattr__(fault,'observation',observation)
        BaseException.__setattr__(fault,'native_preflight_cancelled',events.cancelled)
        BaseException.__setattr__(fault,'native_preflight_cleanup_uncertain',cleanup_fault or birth_attempted and not observation['direct_child_reaped'])
        BaseException.__setattr__(fault,'native_preparation_streams',tuple(quarantined))
        BaseException.__setattr__(fault,'native_preparation_process',process if not observation['direct_child_reaped'] else None)
        raise fault
    alive(cleanup_end)
    return result, observation

