"""Closed-by-default POSIX descriptor adapter; live calls require Root admission."""
import os
import re
import signal
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from types import MappingProxyType

ROOT_ADMISSION_TYPE = None
MAX_HANDLES = 256
MAX_NODES = 128
MAX_DEPTH = 8
MAX_CALLS = 65536
MAX_READ = 65536
MAX_BYTES = 1024 * 1024 * 1024
PLAN_KEYS = frozenset(('files','directories','mkdir_reservations','noacquisition_attempts','scanners',
                       'mask_reservations','backend_calls','read_requests','write_requests'))


class Refused(ValueError):
    pass


class NoAcquisition(FileNotFoundError):
    """Backend positively observed ENOENT before any descriptor was allocated."""


@dataclass(frozen=True)
class Route:
    root: str
    relative: str
    uid: int
    gid: int
    mode: int
    max_bytes: int
    writable: bool
    output: bool
    root_identity: object


def parts(value, *, absolute=False, empty=False):
    if type(value) is not str or len(value.encode()) > (4096 if absolute else 256):
        raise Refused('descriptor path bound')
    if absolute:
        if not value.startswith('/'):
            raise Refused('absolute anchor required')
        value = value[1:]
        if not value:
            return ()
    if not value and empty:
        return ()
    result = value.split('/')
    pattern = r'[A-Za-z0-9_.-]{1,255}' if absolute else r'[A-Za-z0-9_.-]{1,64}'
    if len(result) > (32 if absolute else MAX_DEPTH) or any(
        not re.fullmatch(pattern, p) or p in ('.','..') for p in result):
        raise Refused('descriptor path shape')
    return tuple(result)


@contextmanager
def allocation_guard(check, cleanup_check, reserve, released, record, cleanup=False):
    """Defer supported process signals until the returned resource is adopted.

    This is not protection against arbitrary thread exception injection or other
    threads touching the descriptor table. Root must grant exclusive ownership.
    """
    check()
    reservation=reserve()
    saved=None
    body_error=None
    try:
        saved=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        reservation.saved=saved
        check()
        yield
    except BaseException as error:
        body_error=error
        if type(error) is not NoAcquisition:
            record(error,cleanup)
        raise
    finally:
        try:
            cleanup_check()  # No mask restoration after original J permission fails.
            if saved is None:raise Refused('signal mask acquisition uncertain')
            signal.pthread_sigmask(signal.SIG_SETMASK,saved)
            cleanup_check()
            released(reservation)
        except BaseException as error:
            record(error,True)
            if body_error is None:raise


class OSBackend:
    """No constructor syscalls. All allocation/disposal uses adoption callbacks."""
    def __init__(self, check, cleanup_check, record, *, admission=None):
        if ROOT_ADMISSION_TYPE is None or type(admission) is not ROOT_ADMISSION_TYPE or admission.enabled is not True:
            raise Refused('OS backend admission closed')
        admission.check('descriptor')
        if admission.exclusive_fd_owner is not True:raise Refused('OS descriptor exclusivity unproved')
        def work():admission.check('descriptor');return check()
        def cleanup():admission.check('cleanup');return cleanup_check()
        self.check,self.cleanup_check,self.record=work,cleanup,record
        self.mask_pending=[]
        self.mask_allocations=0
    def _reserve_mask(self):
        if self.mask_allocations>=MAX_HANDLES*4:raise Refused('mask reservation bound')
        self.mask_allocations+=1
        reservation=Token(kind='mask');self.mask_pending.append(reservation)
        return reservation
    def _released_mask(self,reservation):self.mask_pending.remove(reservation)
    def _guard(self,cleanup=False):
        return allocation_guard(self.cleanup_check if cleanup else self.check,
                                self.cleanup_check,self._reserve_mask,self._released_mask,self.record,cleanup)
    def allocate(self, parent, name, directory, create, mode, adopt):
        flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        flags |= os.O_RDONLY | os.O_DIRECTORY if directory else (os.O_WRONLY | os.O_CREAT | os.O_EXCL if create else os.O_RDONLY)
        with self._guard():
            try: fd = os.open(name, flags, mode, dir_fd=parent)
            except FileNotFoundError as error: raise NoAcquisition(str(error)) from error
            adopt(fd)
    def stat_fd(self, fd): return os.fstat(fd)
    def stat_at(self, parent, name): return os.stat(name, dir_fd=parent, follow_symlinks=False)
    def mkdir(self, parent, name):
        with self._guard(): os.mkdir(name, 0o755, dir_fd=parent)
    def read(self, fd, n): return os.read(fd, n)
    def rewind(self, fd): return os.lseek(fd, 0, os.SEEK_SET)
    def write(self, fd, data): return os.write(fd, data)
    def sync(self, fd): return os.fsync(fd)
    def chmod(self, fd, mode): os.fchmod(fd, mode)
    def scan(self, fd, limit, adopt, entered, retire):
        with self._guard():
            scanner = os.scandir(fd)
            adopt(scanner)
        result = []
        body_error=None
        try:
            while True:
                self.check()
                try:entry=next(scanner)
                except StopIteration:break
                self.check()
                if len(result) >= limit:
                    raise Refused('enumeration node bound')
                result.append(entry.name)
        except BaseException as error:
            body_error=error;self.record(error,False)
            raise
        finally:
            try:
                self.cleanup_check()
                self.close_scanner(scanner,entered,retire)
            except BaseException as error:
                self.record(error,True)
                if body_error is None:raise
        return tuple(result)
    def close_scanner(self, scanner, entered, retire):
        with self._guard(cleanup=True):
            entered()
            scanner.close()
            retire()
    def dispose(self, fd, entered, retire):
        with self._guard(cleanup=True):
            entered()  # A fault after entry is permanently ambiguous, never retried.
            try:
                os.close(fd)
            except OSError:
                # Even Linux close errno must not turn an unproved state into PASS.
                raise
            retire()


class Token:
    def __init__(self, parent=None, name=None, kind='fd'):
        self.parent, self.name, self.kind = parent, name, kind
        self.fd = None
        self.identity = None
        self.state = 'UNCERTAIN'
        self.disposal_started = False
        self.attempts = 0


class DescriptorOps:
    """One retained descriptor owner and immutable admitted route table.

    Syscall latency is not preemptible. Checks after a returned call observe late
    failure; unreturned or ambiguous calls retain uncertainty and cannot PASS.
    """
    def __init__(self, authority, admission, *, backend=None):
        if ROOT_ADMISSION_TYPE is None or type(admission) is not ROOT_ADMISSION_TYPE:
            raise Refused('Root Admission class not bound')
        if admission.enabled is not True or admission.authority is not authority:
            raise Refused('descriptor admission closed')
        admission.check('descriptor')
        if admission.exclusive_fd_owner is not True:
            raise Refused('exclusive descriptor ownership unproved')
        if type(admission.routes) is not MappingProxyType or not 0 < len(admission.routes) <= MAX_NODES:
            raise Refused('closed route mapping required')
        self.authority, self.admission = authority, admission
        self.uid, self.gid = admission.uid, admission.gid
        self.Identity, self.DirectoryIdentity = admission.identity_type, admission.directory_identity_type
        self.routes = admission.routes
        self.backend = OSBackend(lambda:self._check(),lambda:self._check(cleanup=True),self._fail,admission=admission) if backend is None else backend
        self._tokens, self._dirs = [], {}
        self._cleanup_mode = False
        self._cleanup_stopped = False
        self.failed = False
        self.read_bytes = self.read_calls = self.write_bytes = self.write_calls = 0
        self.backend_calls=self.cleanup_calls=0
        for name, row in self.routes.items():
            parts(name); self._validate_route(row)
        self._validate_plan(admission.allocation_plan)
        admission.claim_descriptor_ops(self)

    def _validate_plan(self, plan):
        if type(plan) is not MappingProxyType or set(plan)!=PLAN_KEYS or any(type(v) is not int or v<0 for v in plan.values()):
            raise Refused('closed allocation plan required')
        if (plan['files']>128 or sum(plan[n] for n in ('files','directories','mkdir_reservations','noacquisition_attempts','scanners'))>MAX_HANDLES or
                plan['mask_reservations']>MAX_HANDLES*4 or plan['backend_calls']>MAX_CALLS or
                plan['read_requests']>MAX_BYTES or plan['write_requests']>MAX_BYTES):
            raise Refused('allocation plan bound')
        # Only definitely regular modes provide a lower bound: a nonempty0755
        # route may be a directory. Exact physical route aliases count once.
        regular={(r.root,r.relative) for r in self.routes.values() if r.relative and r.mode in (0o600,0o644)}
        roots={r.root for r in self.routes.values()}
        if plan['files']<len(regular) or plan['directories']<len(roots):
            raise Refused('allocation plan below route lower bound')
        self.allocation_plan=plan

    def _validate_route(self, row):
        if type(row) is not self.admission.route_type or type(row.root_identity) is not self.DirectoryIdentity:
            raise Refused('route class identity')
        parts(row.root, absolute=True); parts(row.relative, empty=True)
        if any(type(x) is not int or x < 0 for x in (row.uid,row.gid,row.mode,row.max_bytes)) or row.mode not in (0o600,0o644,0o700,0o755) or row.max_bytes > 64*1024*1024:
            raise Refused('route bounds')
        if type(row.writable) is not bool or type(row.output) is not bool:
            raise Refused('route flags')

    def _fail(self, error, cleanup=False):
        self.failed = True
        try: self.authority.record_failure(error, cleanup=cleanup)
        except BaseException: pass

    def _check(self, cleanup=False):
        if cleanup and self._cleanup_stopped:
            raise Refused('descriptor cleanup stopped')
        if self.failed and not cleanup:
            raise Refused('descriptor owner failed')
        try:self.admission.check('cleanup' if cleanup else 'descriptor')
        except BaseException:
            if cleanup:self._cleanup_stopped=True
            raise

    def _call(self, fn, cleanup=False, allow_noacq=False):
        previous=self._cleanup_mode
        cleanup=cleanup or previous
        self._cleanup_mode=cleanup
        try:
            self._check(cleanup)
            result = fn()
            self._check(cleanup)
            return result
        except BaseException as error:
            if type(error) is NoAcquisition and allow_noacq:
                raise
            self._fail(error, cleanup)
            raise
        finally: self._cleanup_mode=previous

    def _backend(self, fn, *args, allow_noacq=False):
        if self._cleanup_mode:
            if self.cleanup_calls>=MAX_HANDLES*8:raise Refused('cleanup callback budget')
            self.cleanup_calls+=1
        else:
            if self.backend_calls>=MAX_CALLS:raise Refused('backend callback budget')
            self.backend_calls+=1
        return self._call(lambda:fn(*args),cleanup=self._cleanup_mode,allow_noacq=allow_noacq)

    def _route(self, name):
        parts(name)
        if name not in self.routes:
            raise Refused('unadmitted exact name')
        return self.routes[name]

    def _new(self, parent=None, name=None, kind='fd', adopt=None):
        if len(self._tokens) >= MAX_HANDLES:
            raise Refused('lifetime allocation bound')
        token = Token(parent,name,kind)
        self._tokens.append(token)  # Journal before allocation starts.
        if adopt is not None: adopt(token)
        return token

    def _identity(self, value):
        if any(type(getattr(value, name)) is not int or getattr(value, name)<0 for name in
               ('st_dev','st_ino','st_uid','st_gid','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')):
            raise Refused('stat numeric shape')
        kind = 'directory' if stat.S_ISDIR(value.st_mode) else 'regular' if stat.S_ISREG(value.st_mode) else 'other'
        return self.Identity(value.st_dev,value.st_ino,value.st_uid,value.st_gid,
                             stat.S_IMODE(value.st_mode),value.st_size,value.st_mtime_ns,
                             value.st_ctime_ns,value.st_nlink,kind)

    def _directory_identity(self, identity):
        return self.DirectoryIdentity(identity.device,identity.inode,identity.uid,identity.gid,identity.mode,identity.kind)

    @staticmethod
    def _stable(i):
        return i.device,i.inode,i.uid,i.gid,i.mode,i.nlink if i.kind == 'regular' else None,i.kind

    def _allocate(self, parent, name, *, directory=False, create=False, mode=0o644, adopt=None):
        token = self._new(parent,name,adopt=adopt)
        def accepted(fd):
            if type(fd) is not int or fd < 0 or token.fd is not None:
                raise Refused('allocation descriptor shape')
            token.fd, token.state = fd, 'OWNED'
        try:
            self._backend(self.backend.allocate,None if parent is None else parent.fd,name,directory,create,mode,accepted,allow_noacq=True)
        except NoAcquisition:
            if token.fd is None: token.state='RETIRED'
            raise
        if token.state != 'OWNED':
            raise Refused('allocation identity uncertain')
        token.identity = self._identity(self._backend(self.backend.stat_fd,token.fd))
        if create:
            self._backend(self.backend.chmod,token.fd,mode)
            token.identity = self._identity(self._backend(self.backend.stat_fd,token.fd))
        return token

    def _verify(self, token):
        if token not in self._tokens or token.state != 'OWNED' or token.disposal_started:
            raise Refused('foreign or uncertain descriptor')
        actual = self._identity(self._backend(self.backend.stat_fd,token.fd))
        if token.identity is None:
            if not self._cleanup_mode:
                raise Refused('initial descriptor identity unobserved')
            # Positively adopted syscall return, never borrowed, exclusive table
            # ownership admission: cleanup may establish its first held identity.
            token.identity=actual
        if self._stable(actual) != self._stable(token.identity):
            token.state = 'UNCERTAIN'
            raise Refused('descriptor identity changed')
        if token.parent is not None and not self._cleanup_mode:
            self._verify(token.parent)
            named = self._identity(self._backend(self.backend.stat_at,token.parent.fd,token.name))
            if self._stable(named) != self._stable(actual):
                raise Refused('named identity changed')
        return actual

    def _dir(self, parent, name, key, *, create=False):
        if key in self._dirs:
            token = self._dirs[key]; self._verify(token); return token
        try:
            token = self._allocate(parent,name,directory=True)
        except NoAcquisition:
            if not create or self._tokens[-1].state!='RETIRED': raise
            # Directory mutation has a durable reservation too; no guessed absence.
            reservation = self._new(parent,name,kind='mkdir')
            self._backend(self.backend.mkdir,parent.fd,name)
            reservation.state = 'RETIRED'
            token = self._allocate(parent,name,directory=True)
        i = token.identity
        if i.kind != 'directory' or i.uid not in (0,self.uid) or i.gid not in (0,self.gid) or i.mode not in (0o700,0o755):
            raise Refused('unsafe directory')
        self._dirs[key] = token
        return token

    def _anchor(self, row):
        root = self._dir(None,'/',())
        key = ()
        for name in parts(row.root,absolute=True):
            key += (name,); root = self._dir(root,name,key)
        if self._directory_identity(self._verify(root)) != row.root_identity:
            raise Refused('admitted root changed')
        return root

    def _parent(self, row, *, create=False):
        token = self._anchor(row)
        chain = [token]
        names = parts(row.relative,empty=True)
        for index,name in enumerate(names[:-1]):
            key = ('relative',row.root)+names[:index+1]
            token = self._dir(token,name,key,create=create); chain.append(token)
        return token, names[-1] if names else None, tuple(chain)

    def open_named(self, name, adopt):
        def work():
            row = self._route(name); parent,leaf,_ = self._parent(row)
            if leaf is None: raise Refused('file route required')
            token = self._allocate(parent,leaf,adopt=adopt)
            token.route=row; token.created=False
            self._validate_file(token,row)
            return token
        return self._call(work)

    def _validate_file(self, token, row):
        i = self._verify(token)
        if i.kind != 'regular' or i.nlink != 1 or (i.uid,i.gid,i.mode) != (row.uid,row.gid,row.mode) or i.size > row.max_bytes:
            raise Refused('admitted regular file mismatch')

    def create_named(self, name, mode, adopt):
        def work():
            row = self._route(name)
            if row.writable is not True or type(mode) is not int or row.mode != mode:
                raise Refused('creation not admitted')
            parent,leaf,_ = self._parent(row,create=True)
            if leaf is None: raise Refused('file route required')
            token = self._allocate(parent,leaf,create=True,mode=mode,adopt=adopt)
            token.route=row; token.created=True
            self._validate_file(token,row)
            return token
        return self._call(work)

    def stat_handle(self, token): return self._call(lambda:self._verify(token))
    def stat_named(self, name):
        def work():
            row=self._route(name); parent,leaf,_=self._parent(row)
            return self._identity(self._backend(self.backend.stat_at,parent.fd,leaf)) if leaf is not None else self._verify(parent)
        return self._call(work)
    def ancestors(self, name):
        def work():
            row=self._route(name); _,_,chain=self._parent(row)
            return tuple(self._directory_identity(self._verify(t)) for t in chain)
        return self._call(work)

    def read(self, token, n):
        def work():
            self._verify(token)
            if type(n) is not int or not 0<n<=MAX_READ or self.read_calls>=MAX_CALLS or self.read_bytes+n>MAX_BYTES:
                raise Refused('read budget')
            self.read_calls+=1; self.read_bytes+=n
            data=self._backend(self.backend.read,token.fd,n)
            if type(data) is not bytes or len(data)>n: raise Refused('read contract')
            self._verify(token); return data
        return self._call(work)
    def rewind(self, token):
        def work():
            self._verify(token)
            if self._backend(self.backend.rewind,token.fd)!=0: raise Refused('rewind contract')
            self._verify(token)
        return self._call(work)
    def write(self, token, data):
        def work():
            actual=self._verify(token)
            if getattr(token,'created',False) is not True or token.route.writable is not True:
                raise Refused('descriptor write not admitted')
            if type(data) is not bytes or not 0<len(data)<=MAX_READ or self.write_calls>=MAX_CALLS or self.write_bytes+len(data)>MAX_BYTES:
                raise Refused('write budget')
            if actual.size+len(data)>token.route.max_bytes: raise Refused('route write byte bound')
            self.write_calls+=1; self.write_bytes+=len(data)
            result=self._backend(self.backend.write,token.fd,data)
            if type(result) is not int or result!=len(data): raise Refused('short or invalid write')
            self._verify(token)
        return self._call(work)
    def finish_write(self, token):
        def work(): self._verify(token); self._backend(self.backend.sync,token.fd); self._verify(token)
        return self._call(work)
    def borrow_fd(self, token): return self._call(lambda:self._verify(token) and token.fd)

    def output_owned(self, name):
        def work():
            row=self._route(name)
            if row.output is not True: return False
            self._anchor(row)
            return self.admission.output_owned(name) is True
        return self._call(work)

    def list_names(self, name, limit):
        def work():
            if type(limit) is not int or not 0<limit<=MAX_NODES: raise Refused('enumeration bound')
            row=self._route(name); parent,leaf,_=self._parent(row)
            directory=parent if leaf is None else self._dir(parent,leaf,('listing',name))
            found=[]
            def visit(token, prefix):
                scanner=self._new(kind='scanner')
                def adopted(value): scanner.fd=value; scanner.state='OWNED'
                def entered(): scanner.state='UNCERTAIN';scanner.disposal_started=True
                def retired(): scanner.state='RETIRED'
                names=self._backend(self.backend.scan,token.fd,limit-len(found)+1,adopted,entered,retired)
                if scanner.state!='RETIRED' or type(names) is not tuple or len(set(names))!=len(names): raise Refused('scanner disposition')
                for item in names:
                    parts(item)
                    if '/' in item or len(found)>=limit: raise Refused('enumeration bound')
                    relative=prefix+(item,)
                    if len(relative)>MAX_DEPTH: raise Refused('enumeration depth')
                    full='/'.join(relative); found.append(full)
                    actual=self._identity(self._backend(self.backend.stat_at,token.fd,item))
                    if actual.kind=='directory':
                        child=self._dir(token,item,('listing',name)+relative); visit(child,relative)
                    elif actual.kind!='regular' or actual.nlink!=1: raise Refused('unsafe enumerated node')
            visit(directory,()); self._verify(directory)
            return tuple(sorted(found))
        return self._call(work)

    def verify_close_identity(self, token):
        def work():
            if token not in self._tokens: return 'UNKNOWN'
            if token.state=='RETIRED': return 'RETIRED'
            if token.state!='OWNED' or token.disposal_started: return 'UNKNOWN'
            self._verify(token); return 'OWNED'
        return self._call(work,cleanup=True)
    def close(self, token):
        def work():
            if self.verify_close_identity(token)!='OWNED': raise Refused('close identity unknown')
            token.attempts+=1
            if token.attempts>3: raise Refused('lifetime close bound')
            def entered(): token.disposal_started=True; token.state='UNCERTAIN'
            def retired(): token.state='RETIRED'
            self._backend(self.backend.dispose,token.fd,entered,retired)
            if token.state!='RETIRED': raise Refused('retirement unproved')
        return self._call(work,cleanup=True)
    def is_closed(self, token): return self._call(lambda:token in self._tokens and token.state=='RETIRED',cleanup=True)

    def cleanup_all(self):
        """Reverse allocation order. Ambiguous disposal is never numerically retried."""
        for token in reversed(self._tokens):
            try: self._check(cleanup=True)
            except BaseException as error:
                self._fail(error,cleanup=True); break
            if token.state=='RETIRED': continue
            try:
                if token.kind=='scanner' and token.state=='OWNED':
                    def entered():token.state='UNCERTAIN';token.disposal_started=True
                    self._call(lambda:self._backend(self.backend.close_scanner,token.fd,entered,lambda:setattr(token,'state','RETIRED')),cleanup=True)
                elif token.kind=='fd' and self.verify_close_identity(token)=='OWNED': self.close(token)
                else: self._fail(Refused('cleanup ownership uncertain'),cleanup=True)
            except BaseException as error: self._fail(error,cleanup=True)
        return not self.failed and all(t.state=='RETIRED' for t in self._tokens) and not getattr(self.backend,'mask_pending',())
