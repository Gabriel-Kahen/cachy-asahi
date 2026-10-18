#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic offline payload commits in a guarded private Linux namespace only."""
import argparse
import ctypes as C
from contextlib import contextmanager
import fcntl
import gzip
import hashlib
import io
import json
import lzma
import math
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import types
import time

LIBRARY = Path('/usr/lib/libalpm.so.16.0.1')
LIBRARY_SHA = 'da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888'
NATIVE_LIBRARY_SHA = '94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902'
NATIVE_PROFILE_SHA = 'b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8'
NATIVE_RECEIVER_SHA = 'fe2becb4fe6c22e50903ab390db5a79aae311b7284fc71bf4b1c4b79e99824c4'
RUNTIME_SHA = '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'
MAX_PACKAGES, MAX_ARCHIVE, MAX_INPUTS, MAX_TREE = 128, 8 * 1024**2, 32 * 1024**2, 128 * 1024**2
FLAGS = (1 << 7) | (1 << 10)  # NOHOOKS | NOSCRIPTLET, retaining dependencies/conflicts/lock.
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9@+_.-]{0,127}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
FPR = re.compile(r'[0-9A-F]{40}\Z')
TASK_DEADLINE = None
OWNED_OUTPUT = None
ENGINE_STARTED = False
OWNED_CAPSULES = None
EXECUTED_WORKER_SHA = globals().get('EXECUTED_WORKER_SHA')
RUNTIME_BYTES = globals().get('RUNTIME_BYTES')
ENGINE_SPEC_BYTES = globals().get('ENGINE_SPEC_BYTES')
INHERITED_EVIDENCE_FD = globals().get('INHERITED_EVIDENCE_FD')

# The supervisor closes inherited FDs. Acquire only the retained parent's exact
# directory before execing unshare; the inner worker closes this old-mount FD.
OUTER_LOADER = '''import os,sys,stat,fcntl
parent,fd,dev,ino,wfd,wdev,wino,rfd,rdev,rino=map(int,sys.argv[1:11])
assert os.getppid()==parent
owned=os.open('/proc/%d/fd/%d'%(parent,fd),os.O_RDONLY|os.O_DIRECTORY)
s=os.fstat(owned)
assert stat.S_ISDIR(s.st_mode) and (s.st_dev,s.st_ino)==(dev,ino)
os.set_inheritable(owned,True)
args=sys.argv[11:]
args[args.index('EVIDENCE_FD')]=str(owned)
for old,dev,ino,token in ((wfd,wdev,wino,'WORKER_FD'),(rfd,rdev,rino,'RUNTIME_FD')):
 code=os.open('/proc/%d/fd/%d'%(parent,old),os.O_RDONLY)
 s=os.fstat(code)
 assert stat.S_ISREG(s.st_mode) and (s.st_dev,s.st_ino)==(dev,ino) and fcntl.fcntl(code,fcntl.F_GET_SEALS)&15==15
 os.set_inheritable(code,True);args[args.index(token)]=str(code)
os.execve(args[0],args,dict(os.environ))
'''

CHILD_LOADER = '''import os,sys,stat,hashlib,json,fcntl
wfd,pin,spec,sp,efd,rfd,rpin=sys.argv[1:]
def read(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno())
  assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=limit
  data=f.read(limit+1)
  assert len(data)==s.st_size
  return data
def sealed(fd):
 fd=int(fd);s=os.fstat(fd)
 assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=131072 and fcntl.fcntl(fd,fcntl.F_GET_SEALS)&15==15
 os.lseek(fd,0,os.SEEK_SET);data=os.read(fd,131073)
 assert len(data)==s.st_size
 return data,{'device':s.st_dev,'inode':s.st_ino,'size':len(data),'sha256':hashlib.sha256(data).hexdigest()}
code,wr=sealed(wfd); raw=read(spec,1048576); rt,rr=sealed(rfd)
assert hashlib.sha256(code).hexdigest()==pin and hashlib.sha256(raw).hexdigest()==sp
assert rpin=='8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821' and hashlib.sha256(rt).hexdigest()==rpin
obj=json.loads(raw); fd=int(efd); s=os.fstat(fd)
assert stat.S_ISDIR(s.st_mode) and [s.st_dev,s.st_ino]==obj['evidence_identity']
assert obj['worker_source_sha256']==pin and obj['runtime_source_sha256']==rpin
assert obj['worker_reference']==wr and obj['runtime_reference']==rr
assert set(obj['evidence_nodes'])=={'result.json','candidate-packages.lock'}
for name,identity in obj['evidence_nodes'].items():
 node=os.open(name,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 s=os.fstat(node);os.close(node)
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and [s.st_dev,s.st_ino]==identity
os.close(int(wfd));os.close(int(rfd))
source='sealed-worker.py'
sys.argv=[source,'--engine',spec,'--engine-sha256',sp,'--worker-source-sha256',pin]
exec(compile(code,source,'exec'),{'__name__':'__main__','__file__':source,'EXECUTED_WORKER_SHA':pin,
 'RUNTIME_BYTES':rt,'ENGINE_SPEC_BYTES':raw,'INHERITED_EVIDENCE_FD':fd})
'''


def tick():
    need(TASK_DEADLINE is None or time.monotonic() < TASK_DEADLINE, 'aggregate deadline exhausted')


def need(value, message):
    if not value: raise ValueError(message)


def unique(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'duplicate JSON key'); value[key] = item
    return value


def decode(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'nonfinite JSON'))


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def sealed_source(data, label, *, registry=None):
    need(type(data) is bytes and 0 < len(data) <= 128 * 1024, 'finite source bytes required')
    if registry is not None: need(len(registry.owned) < 2, 'finite source capsule registry required')
    fd = None
    try:
        with runtime().defer_signals() as deferred:
            fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            if registry is not None: registry.add(fd)
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining); need(written > 0, 'source capsule write made no progress'); remaining = remaining[written:]
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        if deferred: raise runtime().Cancelled(deferred[0])
        return fd
    except BaseException:
        if registry is None and fd is not None: os.close(fd)
        raise


def source_reference(fd, pin):
    info = os.fstat(fd)
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size, 'sha256': pin}


class SourceCapsules:
    """At most two exact FD leases; persistent refusal retains explicit ownership."""
    def __init__(self): self.owned = {}; self.last_report = None
    def add(self, fd):
        need(type(fd) is int and fd not in self.owned and len(self.owned) < 2, 'finite source capsule registry required')
        self.owned[fd] = None  # Never lose a newly allocated lease if identity capture fails.
        first = None
        for _ in range(3):
            try:
                info = os.fstat(fd); need(stat.S_ISREG(info.st_mode), 'regular source capsule required')
                self.owned[fd] = (info.st_dev, info.st_ino); break
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first
    def dispose(self, prior_error=None):
        first = None; attempts = 0; closed = 0; changed = 0
        def failed(error):
            nonlocal first
            if first is None: first = error
        def still_owned(fd, identity):
            nonlocal closed, changed
            try: info = os.fstat(fd)
            except OSError as error:
                if error.errno == 9:
                    del self.owned[fd]; closed += 1; return False
                failed(error); return None
            except BaseException as error: failed(error); return None
            if identity is None:
                failed(ValueError('source capsule identity unavailable; ownership retained')); return None
            if (info.st_dev, info.st_ino) != identity:
                # The original lease is gone; do not close a reused foreign FD number.
                del self.owned[fd]; changed += 1; failed(ValueError('source capsule descriptor identity changed')); return False
            return True
        deferred = []
        try:
            with runtime().defer_signals() as deferred:
                for fd, identity in tuple(self.owned.items()):
                    for _ in range(3):
                        state = still_owned(fd, identity)
                        if state is False: break
                        if state is None: continue
                        attempts += 1
                        try: os.close(fd)
                        except BaseException as error: failed(error)
                        state = still_owned(fd, identity)  # close can take effect before raising.
                        if state is False: break
                        if state is True: failed(ValueError('source capsule close did not close owned descriptor'))
        except BaseException as error: failed(error)
        if deferred: failed(runtime().Cancelled(deferred[0]))
        if self.owned: failed(ValueError('source capsule cleanup incomplete; ownership retained'))
        self.last_report = {'status': 'FAIL' if first is not None else 'PASS', 'close_attempts': attempts,
            'closed_leases': closed, 'changed_leases': changed, 'owned_remaining': len(self.owned),
            'first_error_type': type(first).__name__ if first is not None else None}
        if first is not None and prior_error is None: raise first
        return self.last_report
    @contextmanager
    def cleanup_scope(self):
        try: yield
        finally: self.dispose(prior_error=sys.exc_info()[1])


def environment(**extra):
    value = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
    if 'HOME' in os.environ: value['HOME'] = os.environ['HOME']
    value.update(extra); return value


def validate_gpg_home_path(workspace):
    # Linux pathname socket budget includes the terminating NUL byte.
    need(len(os.fsencode(Path(workspace) / 'gpg' / 'S.gpg-agent')) <= 107,
         'GPG_HOME_SOCKET_PATH_TOO_LONG')


def private(path, uid):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical private path required')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o700, 'private directory ownership required')
    return path


class Evidence:
    """Retain custody even when the ordinary pathname is renamed or replaced."""
    def __init__(self, path, fd=None, identity=None, *, inplace=False):
        self.path = Path(path)
        self.nodes = {}; self.pending = []; self.retired = []; self.inplace = inplace
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) if fd is None else fd
        info = os.fstat(self.fd); self.identity = (info.st_dev, info.st_ino)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700 and
             (identity is None or tuple(identity) == self.identity), 'evidence directory identity refused')
        try: self.check()
        except BaseException: self.close(); raise

    def __str__(self): return str(self.path)
    def view(self): return Path('/proc/self/fd/' + str(self.fd))
    def duplicate(self):
        """A bounded revocation loan; no new authoritative filesystem node is created."""
        copy = object.__new__(Evidence); copy.path = self.path; copy.identity = self.identity; copy.inplace = self.inplace
        copied = {}
        def dup(fd):
            if fd not in copied: copied[fd] = os.dup(fd)
            return copied[fd]
        try:
            copy.fd = dup(self.fd)
            copy.nodes = {name: (dup(fd), identity) for name, (fd, identity) in self.nodes.items()}
            copy.pending = [(name, dup(fd), identity, temporary) for name, fd, identity, temporary in self.pending]
            copy.retired = [(name, dup(fd), identity) for name, fd, identity in self.retired]
            return copy
        except BaseException:
            for fd in copied.values(): os.close(fd)
            raise
    def close(self):
        closed = set()
        files = {fd for fd, _ in self.nodes.values()} | {row[1] for row in self.pending} | {row[1] for row in self.retired}
        try:
            for fd in [*files, *([self.fd] if self.fd is not None else [])]:
                try: os.close(fd); closed.add(fd)
                except BaseException:
                    try: os.fstat(fd)
                    except OSError as error:
                        if error.errno == 9: closed.add(fd)  # close may have taken effect before interruption.
                    raise
        finally:
            self.nodes = {name: row for name, row in self.nodes.items() if row[0] not in closed}
            self.pending = [row for row in self.pending if row[1] not in closed]
            self.retired = [row for row in self.retired if row[1] not in closed]
            if self.fd in closed: self.fd = None
    def check(self):
        need(self.fd is not None and not any(p.is_symlink() for p in (self.path, *self.path.parents)), 'evidence pathname replaced')
        current = self.path.stat(); held = os.fstat(self.fd)
        need((current.st_dev, current.st_ino) == self.identity == (held.st_dev, held.st_ino) and
             stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,
             'evidence pathname identity differs')
    @staticmethod
    def name(value):
        need(type(value) is str and value not in {'', '.', '..'} and '/' not in value and '\x00' not in value, 'fixed evidence filename required')
        return value
    def adopt(self, name, identity):
        fd = os.open(self.name(name), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        info = os.fstat(fd)
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                (info.st_dev, info.st_ino) == tuple(identity)):
            os.close(fd); raise ValueError('evidence file identity refused')
        if name in self.nodes: os.close(self.nodes[name][0])
        self.nodes[name] = (fd, (info.st_dev, info.st_ino))
    def node_identity(self, name): return list(self.nodes[self.name(name)][1])
    def check_node(self, name):
        if name not in self.nodes: return
        fd, identity = self.nodes[name]; info = os.fstat(fd)
        current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        need(stat.S_ISREG(current.st_mode) and stat.S_ISREG(info.st_mode) and info.st_nlink == current.st_nlink == 1 and
             current.st_uid == info.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == stat.S_IMODE(info.st_mode) == 0o600 and
             (current.st_dev, current.st_ino) == identity == (info.st_dev, info.st_ino), 'evidence file pathname replaced')
    def read(self, name, maximum=1024**2, *, checked=True):
        if checked: self.check()
        name = self.name(name)
        if checked: self.check_node(name)
        fd = os.dup(self.nodes[name][0]) if name in self.nodes else os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        with os.fdopen(fd, 'rb') as stream:
            stream.seek(0)
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and (info.st_nlink == 1 if checked else info.st_nlink in (0, 1)) and
                 0 <= info.st_size <= maximum, 'bounded evidence file required')
            if checked: need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'owned evidence file mode required')
            data = stream.read(info.st_size + 1); after = os.fstat(stream.fileno())
            need(len(data) == info.st_size and (info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                 (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'evidence file changed')
        if checked: self.check()
        return data
    def unlink(self, name, *, checked=True):
        if checked: self.check()
        name = self.name(name)
        try:
            current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            owned = ([self.nodes[name][1]] if name in self.nodes else []) + [row[2] for row in self.pending if row[0] == name]
            if (current.st_dev, current.st_ino) not in owned:
                if checked: raise ValueError('unowned evidence name refused')
                return
            os.unlink(name, dir_fd=self.fd)
        except FileNotFoundError: pass
        os.fsync(self.fd)
    def overwrite(self, name, data):
        need(name in self.nodes and type(data) is bytes and len(data) <= 1024**2, 'retained evidence inode required')
        fd, identity = self.nodes[name]; info = os.fstat(fd)
        need((info.st_dev, info.st_ino) == identity, 'retained evidence inode changed')
        os.lseek(fd, 0, os.SEEK_SET); os.ftruncate(fd, 0)
        with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
    def revoke(self, result):
        need(type(result) is dict and result.get('status') == 'FAIL', 'only failed evidence may be revoked')
        data = (json.dumps(result, sort_keys=True, allow_nan=False) + '\n').encode()
        need(len(data) <= 1024**2, 'failed receipt bound')
        for name, fd, identity, temporary in self.pending + [(name, fd, identity, '') for name, fd, identity in self.retired]:
            if name not in {'result.json', 'candidate-packages.lock', 'installed-packages.lock'}: continue
            info = os.fstat(fd); need((info.st_dev, info.st_ino) == identity, 'pending evidence identity changed')
            payload = data if name == 'result.json' else b'REVOKED\n'
            os.lseek(fd, 0, os.SEEK_SET); os.ftruncate(fd, 0)
            with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            try:
                current = os.stat(temporary, dir_fd=self.fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity: os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError: pass
        for name in ('installed-packages.lock', 'candidate-packages.lock'):
            if name in self.nodes: self.overwrite(name, b'REVOKED\n')
            self.unlink(name, checked=False)
        if 'result.json' in self.nodes: self.overwrite('result.json', data)
        # Create a new FAIL name only when no foreign node occupies that name.
        try: current = os.stat('result.json', dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError: self.write('result.json', data, exclusive=True, checked=False); return
        os.fsync(self.fd)
    def write(self, name, data, *, exclusive=False, checked=True):
        if checked: self.check()
        name = self.name(name); need(type(data) is bytes and len(data) <= 1024**2, 'evidence byte bound')
        if name in self.nodes:
            if checked: self.check_node(name)
            if self.inplace and not exclusive:
                self.overwrite(name, data)
                if checked: self.check_node(name); self.check()
                return
        else: exclusive = True  # An absent destination is never replaced speculatively.
        target = name if exclusive else '.' + name + '-' + os.urandom(8).hex()
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        info = os.fstat(fd); pending = (name, fd, (info.st_dev, info.st_ino), target)
        self.pending.append(pending)  # Track the new inode before any data or replace side effect.
        try:
            with os.fdopen(os.dup(fd), 'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
            if not exclusive:
                if checked: self.check()
                self.check_node(name)  # Staging/fsync may have allowed a destination replacement.
                # POSIX offers no identity CAS rename: a residual check/rename race remains.
                os.replace(target, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            if name in self.nodes: self.retired.append((name, *self.nodes[name]))
            self.nodes[name] = (fd, pending[2]); self.pending.remove(pending); fd = None
            os.fsync(self.fd)
        finally:
            if not exclusive:
                try:
                    current = os.stat(target, dir_fd=self.fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) == pending[2]: os.unlink(target, dir_fd=self.fd)
                except FileNotFoundError: pass
        if checked: self.check_node(name); self.check()
    def save(self, name, value, *, checked=True):
        self.write(name, (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode(), checked=checked)


def capture(reference, maximum=MAX_ARCHIVE):
    tick()
    need(type(reference) is dict and set(reference) == {'path', 'size', 'sha256'}, 'exact file reference required')
    need(type(reference['path']) is str, 'string file reference path required')
    path = Path(reference['path']); size = reference['size']
    need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)) and
         type(size) is int and 0 < size <= maximum and type(reference['sha256']) is str and HEX.fullmatch(reference['sha256']), 'bounded regular reference required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022 and info.st_size == size, 'input file type/mode/size refused')
        data = stream.read(size + 1); after = os.fstat(stream.fileno())
    need((info.st_size, info.st_mtime_ns, info.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
         len(data) == size and hashlib.sha256(data).hexdigest() == reference['sha256'], 'input bytes differ')
    return data


def package_map(value):
    need(type(value) is dict and len(value) <= MAX_PACKAGES, 'finite package map required')
    for name, version in value.items():
        need(type(name) is str and NAME.fullmatch(name) and type(version) is str and
             0 < len(version) <= 128 and not re.search(r'[\s\x00]', version), 'package identity refused')
    return dict(value)


def declared_after(before, add, remove):
    result = dict(before)
    for name, version in remove.items():
        need(result.get(name) == version and name not in add, 'remove identity differs or overlaps add')
        del result[name]
    result.update(add)
    return result


def check_inventory(actual, expected, label):
    need(package_map(actual) == package_map(expected), label + ' inventory differs')


def check_prepared(actual_add, actual_remove, planned_add, planned_remove):
    check_inventory(actual_add, planned_add, 'prepared add')
    check_inventory(actual_remove, planned_remove, 'prepared remove')


def bounded_read(path, maximum=1024**2):
    """Receipt cleanup remains finite even when the work deadline has expired."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum, 'bounded receipt file required')
        data = stream.read(info.st_size + 1)
        need(len(data) == info.st_size, 'receipt changed while reading')
    return data


def read_result(path, *, checked=True):
    record = decode(path.read('result.json', checked=checked) if isinstance(path, Evidence) else bounded_read(path))
    need(type(record) is dict and record.get('status') in {'FAIL', 'PROVISIONAL-disposable-payload-transaction', 'PASS-disposable-payload-transaction'}, 'engine receipt refused')
    return record


def architecture_profile(architecture):
    if architecture == 'x86_64':
        return LIBRARY_SHA, 0xc000003e, (42, 44, 46, 307, 425, 426, 427)
    need(architecture == 'aarch64' and type(NATIVE_LIBRARY_SHA) is str and HEX.fullmatch(NATIVE_LIBRARY_SHA) and
         type(NATIVE_PROFILE_SHA) is str and HEX.fullmatch(NATIVE_PROFILE_SHA), 'selected native profile absent')
    return NATIVE_LIBRARY_SHA, 0xc00000b7, (203, 206, 211, 269, 425, 426, 427)


def native_authority(selection_sha256, worker_sha256):
    """Native direct CLI also checks complete fixed image/tool/source input facts."""
    need(type(NATIVE_RECEIVER_SHA) is str and HEX.fullmatch(NATIVE_RECEIVER_SHA), 'native receiver source grant absent')
    path=Path(__file__).absolute().with_name('native_arm_trial.py')
    data=capture({'path':str(path),'size':path.stat().st_size,'sha256':NATIVE_RECEIVER_SHA},128*1024)
    receiver=types.ModuleType('captured_native_receiver');receiver.__file__=str(path)
    exec(compile(data,str(path),'exec'),receiver.__dict__)
    need(hashlib.sha256(receiver.PROFILE_BYTES).hexdigest()==NATIVE_PROFILE_SHA, 'native receiver profile differs')
    raw=capture({'path':'/inputs/trial.json','size':Path('/inputs/trial.json').stat().st_size,'sha256':selection_sha256},1024**2)
    selection=receiver.validate_selection(receiver.strict(raw))
    need(raw==(json.dumps(selection,sort_keys=True)+'\n').encode() and selection['phase']=='matrix' and
         selection['sources']['scripts/install/local_transaction.py']['sha256']==worker_sha256, 'native source/phase selection differs')
    receiver.source_blobs(selection,Path('/source'),TASK_DEADLINE)
    receiver.verify_environment(selection,TASK_DEADLINE)


GENERIC_VM_CONTRACT = Path('/usr/local/share/virtual-proof/virtual-contract.json')
GENERIC_SOURCE_ROOT = GENERIC_VM_CONTRACT.parent / 'transaction-source'
GENERIC_PROFILE = GENERIC_VM_CONTRACT.parent / 'tool-profile.json'
GENERIC_SCOPE = 'generic-aarch64-fixture'
GENERIC_SOURCE_NAMES = ('scripts/install/local_transaction.py', 'scripts/install/test_local_transaction.py',
                        'scripts/port/kernel-native-job/runtime.py')


def generic_readonly(path, size, pin, maximum, *, single=True):
    """Read fixed root-owned guest inputs/tools; this is not VM attestation."""
    tick(); path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and type(size) is int and 0 < size <= maximum and
         type(pin) is str and HEX.fullmatch(pin) and not any(p.is_symlink() for p in (path, *path.parents)),
         'generic fixture input reference refused')
    for parent in path.parents:
        info = parent.stat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022,
             'generic fixture protected parent required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and not before.st_mode & 0o022 and
             (not single or before.st_nlink == 1) and before.st_size == size, 'generic fixture protected file required')
        raw = stream.read(size + 1); after = os.fstat(stream.fileno())
    stable = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_mtime_ns, st.st_ctime_ns)
    need(stable(before) == stable(after) and len(raw) == size and hashlib.sha256(raw).hexdigest() == pin,
         'generic fixture input bytes changed')
    tick(); return raw


def generic_vm_data(value, worker_sha256):
    """Join reviewed VM-owner data. External Root selection stays a premise."""
    need(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version'] == 1 and
         value.get('execution') == 'qemu-tcg-generic-aarch64' and value.get('purpose') == 'installer-transaction-only' and
         type(value.get('source_commit')) is str and re.fullmatch('[0-9a-f]{40}', value['source_commit']) and
         type(value.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']) and
         type(value.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}', value['image_id']),
         'generic fixture VM data differs')
    fixture = value.get('transaction_fixture')
    need(type(fixture) is dict and set(fixture) == {'source_commit', 'sources', 'tool_profile'} and
         type(fixture['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', fixture['source_commit']) and
         type(fixture['sources']) is dict and set(fixture['sources']) == set(GENERIC_SOURCE_NAMES),
         'generic fixture Source data differs')
    for row in fixture['sources'].values():
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and
             0 < row['bytes'] <= 128*1024 and type(row['sha256']) is str and HEX.fullmatch(row['sha256']),
             'generic fixture Source reference differs')
    need(type(worker_sha256) is str and HEX.fullmatch(worker_sha256) and
         fixture['sources'][GENERIC_SOURCE_NAMES[0]]['sha256'] == worker_sha256 and
         fixture['sources'][GENERIC_SOURCE_NAMES[2]]['sha256'] == RUNTIME_SHA,
         'generic fixture worker/runtime pin differs')
    profile = fixture['tool_profile']
    need(type(profile) is dict and set(profile) == {'path', 'size', 'sha256'} and
         profile['path'] == str(GENERIC_PROFILE) and type(profile['size']) is int and profile['size'] == 47593 and
         profile['sha256'] == NATIVE_PROFILE_SHA, 'generic fixture fixed tool-profile data differs')
    return fixture


def generic_preflight(vm_contract, vm_sha256, worker_sha256):
    """No GPG/CDLL/process action. Refuse the unchanged boot's unestablished NNP/caps."""
    need(Path(vm_contract) == GENERIC_VM_CONTRACT and type(vm_sha256) is str and HEX.fullmatch(vm_sha256),
         'generic fixture exact VM contract required')
    need(sys.platform == 'linux' and os.uname().machine == 'aarch64' and
         os.uname().release == '7.2.10-1-aarch64-ARCH' and os.sysconf('SC_PAGE_SIZE') == 4096 and
         os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 23001,
         'generic fixture ordinary guest required')
    status = {}
    for name, maximum in (('/proc/self/status', 65536), ('/proc/cmdline', 4096)):
        with open(name, 'rb') as stream: raw = stream.read(maximum + 1)
        need(len(raw) <= maximum, 'generic fixture proc bound')
        if name.endswith('status'):
            for line in raw.decode('ascii').splitlines():
                if ':' in line:
                    key, text = line.split(':', 1)
                    need(key not in status, 'generic fixture duplicate proc field'); status[key] = text.strip()
        else:
            need('cachy_asahi_virtual_proof=1' in raw.decode('ascii').split(), 'generic fixture real guest marker required')
    need(status.get('NoNewPrivs') == '1' and all(status.get(key) is not None and
         re.fullmatch('[0-9a-fA-F]{1,16}', status[key]) and int(status[key], 16) == 0
         for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd')), 'generic fixture zero-capability NNP parent required')
    raw = generic_readonly(GENERIC_VM_CONTRACT, GENERIC_VM_CONTRACT.stat().st_size, vm_sha256, 1024**2)
    value = decode(raw); fixture = generic_vm_data(value, worker_sha256)
    need(Path(__file__).absolute() == GENERIC_SOURCE_ROOT / GENERIC_SOURCE_NAMES[0], 'generic fixture fixed worker location required')
    for name, row in fixture['sources'].items():
        generic_readonly(GENERIC_SOURCE_ROOT / name, row['bytes'], row['sha256'], 128*1024)
    ref = fixture['tool_profile']
    profile = decode(generic_readonly(GENERIC_PROFILE, ref['size'], ref['sha256'], 1024**2))
    need(profile.get('architecture') == 'aarch64' and profile.get('libalpm_expected_abi') == '16.0.1' and
         type(profile.get('files')) is list and len(profile['files']) == 136 and
         sum(row['size'] for row in profile['files']) == 85445048, 'generic fixture tool closure differs')
    for alias, target in profile['aliases'].items():
        tick(); need(str(Path(alias).resolve(strict=True)) == target, 'generic fixture tool alias differs')
    libraries = [row for row in profile['files'] if row['path'] == str(LIBRARY)]
    need(len(libraries) == 1 and libraries[0]['sha256'] == architecture_profile('aarch64')[0],
         'generic fixture library profile differs')
    for row in profile['files']:
        generic_readonly(row['path'], row['size'], row['sha256'], 64*1024**2, single=False)
    return value


class GenericDeclaredAfterMismatch(ValueError):
    """Closed generic fixture declaration refusal, before actors or commit."""


def validate_contract(contract, selection_sha256=None, *, generic_vm_contract_sha256=None):
    fields = {'schema_version', 'scope', 'workspace', 'architecture', 'before', 'after', 'protected',
              'add', 'remove', 'keyring', 'timeout_seconds', 'libalpm_sha256'}
    native = type(contract) is dict and contract.get('schema_version') == 2
    generic = type(contract) is dict and contract.get('schema_version') == 3
    extra = {'profile_sha256', 'generic_vm_contract_sha256'} if generic else {'profile_sha256', 'input_selection_sha256'} if native else set()
    need(type(contract) is dict and set(contract) == fields | extra and
         type(contract['schema_version']) is int and contract['schema_version'] == (3 if generic else 2 if native else 1), 'closed transaction contract required')
    if generic:
        need(selection_sha256 is None and type(generic_vm_contract_sha256) is str and HEX.fullmatch(generic_vm_contract_sha256) and
             contract['scope'] == GENERIC_SCOPE and contract['architecture'] == 'aarch64' and
             contract['generic_vm_contract_sha256'] == generic_vm_contract_sha256 and
             contract['profile_sha256'] == NATIVE_PROFILE_SHA and
             contract['libalpm_sha256'] == architecture_profile('aarch64')[0], 'selected generic fixture required')
    elif native:
        need(generic_vm_contract_sha256 is None and contract['scope'] == 'native-aarch64-fixture' and contract['architecture'] == 'aarch64' and
             type(selection_sha256) is str and HEX.fullmatch(selection_sha256) and
             contract['input_selection_sha256'] == selection_sha256 and contract['profile_sha256'] == NATIVE_PROFILE_SHA and
             contract['libalpm_sha256'] == architecture_profile('aarch64')[0], 'selected native fixture profile required')
    else:
        need(contract['scope'] == 'synthetic-fixture' and selection_sha256 is None and generic_vm_contract_sha256 is None,
             'real candidate/unadopted inputs are not authorized by this initial worker')
        need(contract['architecture'] == 'x86_64' and contract['libalpm_sha256'] == LIBRARY_SHA,
             'only pinned x86 synthetic engine supported')
    need(type(contract['timeout_seconds']) is int and 1 <= contract['timeout_seconds'] <= 1200, 'finite timeout required')
    before, after, protected, remove = [package_map(contract[k]) for k in ('before', 'after', 'protected', 'remove')]
    add = contract['add']; need(type(add) is list and 0 <= len(add) <= MAX_PACKAGES and bool(add or remove), 'finite nonempty add set required')
    planned = {}
    for row in add:
        need(type(row) is dict and set(row) == {'name', 'version', 'archive', 'signature', 'signer'}, 'closed add row required')
        package_map({row['name']: row['version']})
        need(row['name'] not in planned and type(row['signer']) is str and FPR.fullmatch(row['signer']), 'duplicate add or signer refused')
        planned[row['name']] = row['version']
    if native or generic:
        need(all(name.startswith('caa-install-fixture-') or (generic and kind == 'after' and
                 name == 'undeclared-extra' and rows[name] == '1')
                 for kind, rows in (('before', before), ('after', after), ('protected', protected),
                                   ('remove', remove), ('planned', planned)) for name in rows),
             'native profile admits inert fixture identities only')
    after_matches = declared_after(before, planned, remove) == after
    if generic and not after_matches: raise GenericDeclaredAfterMismatch('declared full after map differs')
    need(after_matches, 'declared full after map differs')
    need(all(before.get(n) == after.get(n) == v and n not in planned and n not in remove for n, v in protected.items()), 'protected delta refused')
    need(type(contract['workspace']) is str, 'workspace required')
    return contract


def save(path, value):
    path = Path(path); data = (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()
    if isinstance(OWNED_OUTPUT, Evidence) and path.parent == OWNED_OUTPUT.path:
        OWNED_OUTPUT.save(path.name, value); return
    need(len(data) <= 1024**2, 'receipt bound')
    temp = path.with_name('.' + path.name + '-' + os.urandom(8).hex())
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def runtime():
    global RUNTIME_BYTES
    path = Path('/captured/runtime.py')
    if RUNTIME_BYTES is None:
        path = Path(__file__).resolve().parents[1] / 'port/kernel-native-job/runtime.py'
        RUNTIME_BYTES = capture({'path': str(path), 'size': path.stat().st_size, 'sha256': RUNTIME_SHA}, 128 * 1024)
    data = RUNTIME_BYTES; need(hashlib.sha256(data).hexdigest() == RUNTIME_SHA, 'captured runtime bytes differ')
    value = types.ModuleType('local_transaction_runtime'); value.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), value.__dict__); return value


def supervise(argv, seconds, env, log_dir):
    try: return runtime().Runner(seconds, env, log_dir).run(argv, timeout=seconds, limit=1024**2, log='command.log')
    except ValueError as error:
        if str(error) in ('command-timeout', 'deadline-exhausted'): raise TimeoutError(str(error)) from None
        raise


def revoke_guard_failure(error):
    evidence = OWNED_OUTPUT
    if not isinstance(evidence, Evidence) or evidence.fd is None: return
    with runtime().defer_signals():
        try: record = read_result(evidence, checked=False)
        except BaseException: record = {'commit_started': 'UNKNOWN', 'committed': 'UNKNOWN', 'phase': 'unknown'}
        record.update(status='FAIL', parent_error_type=type(error).__name__, parent_error=str(error)[:512])
        if OWNED_CAPSULES is not None and OWNED_CAPSULES.last_report is not None: record['capsule_cleanup'] = OWNED_CAPSULES.last_report
        evidence.revoke(record)


@contextmanager
def custody_guard(final_check):
    """Keep post-handler custody checks inside deferral; retain authority on restoration."""
    rt = runtime()
    with rt.defer_signals() as deferred:
        try:
            with rt.cancellation_handlers(): yield
            final_check()
            if deferred: raise rt.Cancelled(deferred[0])
        except BaseException as error:
            revoke_guard_failure(error)
            raise
    if deferred:  # A signal may have been routed during the outer handler restoration.
        error = rt.Cancelled(deferred[0]); revoke_guard_failure(error); raise error


def namespaces():
    return {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'pid', 'net')}


def relative(value):
    need(type(value) is str and value and '\x00' not in value and not value.startswith('/') and
         '..' not in value.split('/') and Path(value).as_posix() == value, 'noncanonical payload path')
    return value


def node(path):
    info = path.lstat(); common = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if stat.S_ISREG(info.st_mode):
        need(info.st_nlink == 1 and info.st_size <= MAX_TREE, 'hardlink or oversized file refused')
        return common | {'type': 'file', 'sha256': digest(path), 'bytes': info.st_size}
    if stat.S_ISDIR(info.st_mode): return common | {'type': 'directory'}
    if stat.S_ISLNK(info.st_mode): return common | {'type': 'symlink', 'target': os.readlink(path)}
    raise ValueError('special filesystem node refused')


def tree(root):
    rows, size, pending = {}, 0, [root]
    while pending:
        tick(); directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                tick(); need(len(rows) < 20000, 'filesystem node bound')
                path = Path(entry.path); name = relative(path.relative_to(root).as_posix()); value = node(path)
                need(path.resolve().is_relative_to(root.resolve()), 'escaping existing filesystem link')
                size += value.get('bytes', 0); need(size <= MAX_TREE, 'filesystem byte bound')
                rows[name] = value
                if value['type'] == 'directory': pending.append(path)
    return rows


def copy_tree(source, target):
    rows = tree(source); target.mkdir(mode=0o700)
    for name, value in sorted(rows.items(), key=lambda row: (len(Path(row[0]).parts), row[0])):
        tick(); path = target / name; path.parent.mkdir(parents=True, exist_ok=True)
        if value['type'] == 'directory': path.mkdir(exist_ok=True); path.chmod(value['mode'])
        elif value['type'] == 'symlink': path.symlink_to(value['target'])
        else:
            data = capture({'path': str(source / name), 'size': value['bytes'], 'sha256': value['sha256']}, MAX_TREE) if value['bytes'] else b''
            path.write_bytes(data); path.chmod(value['mode'])
    return tree(target)


def resolve_nodes(rows, name, seen=()):
    parts = []
    for part in name.split('/'):
        if part in ('', '.'): continue
        if part == '..':
            need(parts, 'escaping payload link'); parts.pop(); continue
        parts.append(part); current = '/'.join(parts)
        if rows.get(current, {}).get('type') == 'symlink':
            need(current not in seen and len(seen) < 40, 'cyclic payload link')
            link = rows[current]['target']; need(not link.startswith('/'), 'absolute payload link')
            target = '/'.join(parts[:-1] + [link])
            parts = resolve_nodes(rows, target, (*seen, current)).split('/')
    return '/'.join(parts)


def projected_paths(seed, added):
    combined = dict(seed); combined.update(added)
    need(len(combined) <= 20000 and sum(row.get('bytes', 0) for row in combined.values()) <= MAX_TREE, 'projected node/byte bound')
    for name in combined: resolve_nodes(combined, name)
    for name in ('usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'):
        resolved = resolve_nodes(combined, name)
        need(name not in combined and resolved not in combined, 'unaudited auxiliary executable or alias refused')
    return combined


def archive_payload(path, accounting=None):
    rows, total, seen = {}, 0, set()
    compressed = path if type(path) is bytes else bounded_read(path, MAX_ARCHIVE)
    remaining = MAX_TREE - (accounting['bytes'] if accounting is not None else 0)
    if compressed.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream: decoded = stream.read(remaining + 1)
    else:
        need(compressed.startswith(b'\xfd7zXZ\x00'), 'only bounded gzip/xz fixture archives supported')
        decoder = lzma.LZMADecompressor(memlimit=64 * 1024**2)
        decoded = decoder.decompress(compressed, max_length=remaining + 1)
        need(decoder.eof and not decoder.unused_data, 'xz archive incomplete/concatenated or oversized')
    need(len(decoded) <= remaining, 'aggregate decoded archive byte bound')
    if accounting is not None: accounting['bytes'] += len(decoded)
    with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:') as archive:
        for index, member in enumerate(archive):
            tick(); need(index < 20000 and not member.sparse and not any(k.startswith('GNU.sparse') for k in member.pax_headers), 'archive node/sparse bound')
            name = member.name.removeprefix('./').rstrip('/'); relative(name)
            need(name not in seen and member.uid == member.gid == 0, 'duplicate/nonroot archive member'); seen.add(name)
            total += member.size; need(total <= MAX_TREE, 'decoded archive byte bound')
            if accounting is not None:
                accounting['nodes'] += 1
                need(accounting['nodes'] <= 20000 and accounting['bytes'] <= MAX_TREE, 'aggregate decoded archive bound')
            if name.startswith('.'):
                need(name in {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL', '.CHANGELOG'} and member.isfile(), 'unexpected control member')
                continue
            value = {'mode': member.mode & 0o7777, 'uid': 0, 'gid': 0}
            if member.isdir(): value['type'] = 'directory'
            elif member.isfile():
                value.update(type='file', sha256=hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest(), bytes=member.size)
            elif member.issym():
                need(not member.linkname.startswith('/') and '\x00' not in member.linkname, 'absolute archive link refused')
                value.update(type='symlink', target=member.linkname)
            else: raise ValueError('archive special/hardlink member refused')
            need(name not in {'usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'}, 'unaudited auxiliary ldconfig refused')
            rows[name] = value
    for name in rows: resolve_nodes(rows, name)
    return rows


class List(C.Structure): pass
Ptr = C.POINTER(List)
List._fields_ = [('data', C.c_void_p), ('prev', Ptr), ('next', Ptr)]
class File(C.Structure):
    _fields_ = [('name', C.c_char_p), ('size', C.c_long), ('mode', C.c_uint)]
class Files(C.Structure):
    _fields_ = [('count', C.c_size_t), ('files', C.POINTER(File))]


def pointers(pointer):
    for _ in range(4096):
        if not pointer: return
        yield pointer.contents.data; pointer = pointer.contents.next
    raise ValueError('libalpm list bound')


class Alpm:
    def __init__(self, root, gpgdir, log, architecture='x86_64'):
        need(digest(LIBRARY) == architecture_profile(architecture)[0], 'libalpm binary changed')
        self.lib = C.CDLL(str(LIBRARY)); self.handle = None; self.started = False
        p = C.c_void_p
        functions = {
            'alpm_version': (C.c_char_p, []), 'alpm_initialize': (p, [C.c_char_p, C.c_char_p, C.POINTER(C.c_int)]),
            'alpm_release': (C.c_int, [p]), 'alpm_errno': (C.c_int, [p]), 'alpm_strerror': (C.c_char_p, [C.c_int]),
            'alpm_option_add_architecture': (C.c_int, [p, C.c_char_p]),
            'alpm_option_set_gpgdir': (C.c_int, [p, C.c_char_p]), 'alpm_option_set_logfile': (C.c_int, [p, C.c_char_p]),
            'alpm_option_set_local_file_siglevel': (C.c_int, [p, C.c_int]),
            'alpm_get_localdb': (p, [p]), 'alpm_db_get_pkgcache': (Ptr, [p]), 'alpm_db_get_pkg': (p, [p, C.c_char_p]),
            'alpm_pkg_get_name': (C.c_char_p, [p]), 'alpm_pkg_get_version': (C.c_char_p, [p]),
            'alpm_pkg_get_arch': (C.c_char_p, [p]), 'alpm_pkg_get_files': (C.POINTER(Files), [p]),
            'alpm_pkg_load': (C.c_int, [p, C.c_char_p, C.c_int, C.c_int, C.POINTER(p)]),
            'alpm_add_pkg': (C.c_int, [p, p]), 'alpm_remove_pkg': (C.c_int, [p, p]),
            'alpm_trans_init': (C.c_int, [p, C.c_int]), 'alpm_trans_prepare': (C.c_int, [p, C.POINTER(Ptr)]),
            'alpm_trans_commit': (C.c_int, [p, C.POINTER(Ptr)]), 'alpm_trans_release': (C.c_int, [p]),
            'alpm_trans_get_add': (Ptr, [p]), 'alpm_trans_get_remove': (Ptr, [p])}
        for name, (restype, args) in functions.items():
            function = getattr(self.lib, name); function.restype = restype; function.argtypes = args; setattr(self, name, function)
        need(self.alpm_version() == b'16.0.1', 'libalpm ABI changed')
        db = root / 'var/lib/pacman'; db.mkdir(parents=True, exist_ok=True); (db / 'local').mkdir(exist_ok=True)
        error = C.c_int(); self.handle = self.alpm_initialize(os.fsencode(root), os.fsencode(db), C.byref(error))
        need(self.handle, 'private libalpm initialize failed')
        for method, value in ((self.alpm_option_set_gpgdir, os.fsencode(gpgdir)),
                              (self.alpm_option_set_logfile, os.fsencode(log)),
                              (self.alpm_option_add_architecture, architecture.encode()), (self.alpm_option_set_local_file_siglevel, 1)):
            self.ok(method(self.handle, value), 'private libalpm option')

    def ok(self, code, label):
        need(code == 0, label + ': ' + self.alpm_strerror(self.alpm_errno(self.handle)).decode())

    def packages(self, entries):
        value = {}
        for package in pointers(entries):
            name, version = self.alpm_pkg_get_name(package).decode(), self.alpm_pkg_get_version(package).decode()
            need(name not in value, 'duplicate actual package'); value[name] = version
        return package_map(value)

    def inventory(self): return self.packages(self.alpm_db_get_pkgcache(self.alpm_get_localdb(self.handle)))

    def owned_files(self, names):
        paths = set(); db = self.alpm_get_localdb(self.handle)
        for name in names:
            package = self.alpm_db_get_pkg(db, name.encode()); need(package, 'protected package absent')
            files = self.alpm_pkg_get_files(package).contents; need(files.count <= 20000, 'file-list bound')
            paths.update(relative(files.files[i].name.decode().rstrip('/')) for i in range(files.count))
        return paths

    def close(self):
        if self.started: self.alpm_trans_release(self.handle)
        if self.handle: self.alpm_release(self.handle); self.handle = None


def mount(source, target, flags=0, filesystem=None, options=None):
    libc = C.CDLL(None, use_errno=True)
    function = libc.mount; function.argtypes = [C.c_char_p, C.c_char_p, C.c_char_p, C.c_ulong, C.c_char_p]
    result = function(os.fsencode(source) if source else None, os.fsencode(target),
                      filesystem.encode() if filesystem else None, flags, options.encode() if options else None)
    need(result == 0, 'namespace mount refused: ' + str(C.get_errno()))


def block_service_ipc(architecture='x86_64'):
    """Inherited pathname sockets remain reachable across network namespaces."""
    need(os.uname().machine == architecture, 'unsupported seccomp architecture')
    _, audit_arch, denied = architecture_profile(architecture)
    class Filter(C.Structure):
        _fields_ = [('code', C.c_ushort), ('jt', C.c_ubyte), ('jf', C.c_ubyte), ('k', C.c_uint)]
    class Program(C.Structure):
        _fields_ = [('length', C.c_ushort), ('filters', C.POINTER(Filter))]
    # Native ABI only; x32 numbers and every other audit architecture are killed.
    rows = [(0x20, 0, 0, 4), (0x15, 1, 0, audit_arch), (0x06, 0, 0, 0x80000000), (0x20, 0, 0, 0)]
    if architecture == 'x86_64': rows += [(0x45, 0, 1, 0x40000000), (0x06, 0, 0, 0x80000000)]
    for number in denied:  # Socket sends/connect; io_uring setup/enter/register.
        rows += [(0x15, 0, 1, number), (0x06, 0, 0, 0x00050000 | 1)]  # EPERM.
    rows.append((0x06, 0, 0, 0x7fff0000))
    filters = (Filter * len(rows))(*(Filter(*row) for row in rows)); program = Program(len(rows), filters)
    libc = C.CDLL(None, use_errno=True); libc.prctl.restype = C.c_int
    need(libc.prctl(38, 1, 0, 0, 0) == 0 and libc.prctl(22, 2, C.byref(program), 0, 0) == 0,
         'service IPC seccomp guard refused')


def reduce_capabilities():
    """After the last mount, retain only the existing copied-root ALPM capability set."""
    safe = sum(1 << bit for bit in (0, 1, 3, 6, 7, 18))
    class Header(C.Structure): _fields_ = [('version', C.c_uint), ('pid', C.c_int)]
    class Data(C.Structure): _fields_ = [('effective', C.c_uint), ('permitted', C.c_uint), ('inheritable', C.c_uint)]
    libc = C.CDLL(None, use_errno=True)
    for bit in range(64):
        if safe & (1 << bit): continue
        if libc.prctl(24, bit, 0, 0, 0) != 0:
            need(C.get_errno() == 22, 'capability bounding reduction refused'); break
    need(libc.prctl(47, 4, 0, 0, 0) == 0, 'ambient capability clearing refused')
    header = Header(0x20080522, 0); data = (Data * 2)(Data(safe, safe, 0), Data(0, 0, 0))
    need(libc.capset(C.byref(header), data) == 0, 'capability reduction refused')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(status[key].strip(), 16) == safe for key in ('CapEff', 'CapPrm', 'CapBnd')) and
         all(int(status[key].strip(), 16) == 0 for key in ('CapInh', 'CapAmb')) and status['NoNewPrivs'].strip() == '1',
         'actual reduced capabilities differ')


def public_keyring_only(listing, keys):
    for line in listing.decode().splitlines():
        tag = line.strip().split(':', 1)[0]
        need(tag not in {'sec', 'ssb'}, 'secret key record refused')
        need(tag == 'tru' or line.startswith('gpg: '), 'unexpected secret-listing record')
    directory = keys / 'private-keys-v1.d'
    if directory.exists() or directory.is_symlink():
        need(directory.is_dir() and not directory.is_symlink(), 'private key directory type refused')
        with os.scandir(directory) as entries: need(next(entries, None) is None, 'secret key material refused')


@contextmanager
def namespace_evidence_view(original, expected_namespaces):
    """Lend one checked directory opened through this namespace's named mount."""
    current, identity, current_lease = None, None, None
    retained_lease = tuple(original.identity)
    first, entered, current_mount = None, None, None
    def failed(error):
        nonlocal first
        if first is None: first = error
    def metadata(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)
    def proc(path, limit):
        tick()
        with Path(path).open('rb') as stream: raw = stream.read(limit + 1)
        need(len(raw) <= limit, 'namespace metadata byte bound')
        return raw.decode('utf-8')
    def namespace_check():
        nonlocal entered
        if entered is None:
            need(type(expected_namespaces) is dict, 'closed namespace identity required')
            entered = dict(expected_namespaces)
            need(set(entered) == {'user','mnt','pid','net'} and
                 all(type(value) is str and len(value) <= 64 and re.fullmatch(name + r':\[[0-9]+\]', value)
                     for name, value in entered.items()), 'closed namespace identity required')
        need(namespaces() == entered, 'current evidence namespace identity differs')
    def mount_check():
        nonlocal current_mount
        fields = [row.split(':', 1)[1].strip() for row in proc('/proc/self/fdinfo/' + str(current), 4096).splitlines()
                  if row.startswith('mnt_id:')]
        need(len(fields) == 1 and fields[0].isdigit(), 'evidence descriptor mount identity missing')
        if current_mount is None: current_mount = fields[0]
        need(fields[0] == current_mount, 'evidence descriptor mount identity changed')
        rows = proc('/proc/self/mountinfo', 4 * 1024**2).splitlines()
        need(len(rows) <= 32768 and all(row.split() and row.split()[0].isdigit() for row in rows), 'mount identity inventory refused')
        need(fields[0] in {row.split()[0] for row in rows}, 'evidence descriptor mount outside current namespace')
    try:
        namespace_check(); original.check()
        held = os.fstat(original.fd); identity = metadata(held)
        need(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid() and stat.S_IMODE(held.st_mode) == 0o700 and
             tuple(original.identity) == identity[:2] and not original.nodes and not original.pending and not original.retired,
             'bare retained evidence directory required')
        named = original.path.stat(follow_symlinks=False)
        need(metadata(named) == identity, 'named retained evidence metadata differs')
        # Opening the pathname after namespace entry creates a new mount view.
        # dup(original.fd) or /proc/self/fd/original.fd retains the parent mount.
        with runtime().defer_signals() as deferred:
            current = os.open(original.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            capture_error = None
            for _ in range(3):
                try:
                    current_lease = metadata(os.fstat(current))[:2]; break
                except BaseException as error:
                    if capture_error is None: capture_error = error
            if capture_error is not None: raise capture_error
        if deferred: raise runtime().Cancelled(deferred[0])
        original.check(); namespace_check(); mount_check()
        need(metadata(os.fstat(current)) == identity == metadata(os.fstat(original.fd)) ==
             metadata(original.path.stat(follow_symlinks=False)), 'current evidence directory metadata differs')
        original.check(); namespace_check(); mount_check()
        need(metadata(os.fstat(current)) == identity == metadata(os.fstat(original.fd)) ==
             metadata(original.path.stat(follow_symlinks=False)), 'evidence view changed during validation')
        yield current
    finally:
        prior = sys.exc_info()[1]; deferred = []; attempts = {}
        def close_views():
            for fd, authority, lease in ((current, None, current_lease), (original.fd, original, retained_lease)):
                if fd is None: continue
                for _ in range(3 - attempts.get(fd, 0)):
                    attempts[fd] = attempts.get(fd, 0) + 1
                    try:
                        info = os.fstat(fd)
                        if lease is None: raise ValueError('evidence descriptor lease unavailable; cleanup refused')
                        if metadata(info)[:2] != lease:
                            if authority is not None: authority.fd = None
                            raise ValueError('evidence descriptor lease replaced; foreign descriptor not closed')
                    except OSError as error:
                        if error.errno == 9:
                            if authority is not None: authority.fd = None
                            break
                        failed(error); continue
                    except BaseException as error: failed(error); break
                    try:
                        if authority is None: os.close(fd)
                        else: authority.close()
                    except BaseException as error: failed(error)
                else: failed(ValueError('evidence descriptor cleanup incomplete'))
        try:
            with runtime().defer_signals() as deferred: close_views()
        except BaseException as error:
            failed(error); close_views()  # Guard setup/restore failure cannot skip owned cleanup.
        if deferred: failed(runtime().Cancelled(deferred[0]))
        if first is not None and prior is None: raise first


def isolate(spec):
    global OWNED_OUTPUT
    architecture = spec['contract'].get('architecture', 'x86_64')
    architecture_profile(architecture)
    need(sys.platform == 'linux' and os.uname().machine == architecture and os.getuid() == os.geteuid() == 0,
         'mapped x86 Linux namespace required')
    entered_namespaces = namespaces()
    need(Path('/proc/self/uid_map').read_text().split() == ['0', str(spec['host_uid']), '1'] and
         spec['host_uid'] != 0 and all(entered_namespaces[k] != v for k, v in spec['host_namespaces'].items()) and os.getpid() == 1,
         'actual namespace identity/map refused')
    workspace = Path(spec['contract']['workspace']); private(workspace, 0); private(workspace / 'evidence', 0)
    need(type(INHERITED_EVIDENCE_FD) is int and INHERITED_EVIDENCE_FD >= 3, 'retained inherited evidence FD required')
    original = Evidence(workspace / 'evidence', INHERITED_EVIDENCE_FD, spec['evidence_identity'])
    with namespace_evidence_view(original, entered_namespaces) as outfd:
        device_numbers = {'null': 3, 'zero': 5, 'random': 8, 'urandom': 9}
        devices = {name: os.open('/dev/' + name, os.O_PATH | os.O_NOFOLLOW) for name in device_numbers}
        for name, fd in devices.items():
            info = os.fstat(fd)
            need(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 1 and os.minor(info.st_rdev) == device_numbers[name], 'device identity refused')
        mount(None, '/', (1 << 14) | (1 << 18))  # MS_REC | MS_PRIVATE first.
        mount('/', '/', (1 << 12) | (1 << 14))  # Recursive bind owned by this namespace.
        class Attr(C.Structure): _fields_ = [(key, C.c_ulonglong) for key in ('set', 'clear', 'propagation', 'userns')]
        libc = C.CDLL(None, use_errno=True); attr = Attr(1, 0, 0, 0)
        need(libc.syscall(442, -100, b'/', 0x8000, C.byref(attr), C.sizeof(attr)) == 0, 'recursive read-only barrier refused')
        mount('tmpfs', workspace, 2 | 4, 'tmpfs', 'size=384m,mode=0700')
        (workspace / 'evidence').mkdir(mode=0o700)
        mount('/proc/self/fd/' + str(outfd), workspace / 'evidence', 1 << 12)
    OWNED_OUTPUT = Evidence(workspace / 'evidence', identity=spec['evidence_identity'], inplace=True)
    mount(None, workspace / 'evidence', (1 << 5) | (1 << 12) | 2 | 4)  # Remount own evidence RW,nosuid,nodev.
    for name, identity in spec['evidence_nodes'].items(): OWNED_OUTPUT.adopt(name, identity)
    mount('tmpfs', '/dev', 2, 'tmpfs', 'size=1m,mode=0755')
    for name, descriptor in devices.items():
        target = Path('/dev') / name; target.touch()
        mount('/proc/self/fd/' + str(descriptor), target, 1 << 12)
        mount(None, target, (1 << 5) | (1 << 12) | 1 | 2)  # Allowed device binds read-only, not nodev.
        os.close(descriptor)
    observed = Path('/proc/self/mountinfo').read_text().splitlines()
    writable = []
    for row in observed:
        fields = row.split(); target = fields[4]; options = set(fields[5].split(','))
        need(not any(v.startswith(('shared:', 'master:')) for v in fields[6:fields.index('-')]), 'mount propagation is not private')
        if 'rw' in options:
            need(target == '/dev' or target == str(workspace) or target == str(workspace / 'evidence'), 'unexpected writable inherited mount')
            writable.append(target)
    need(str(workspace) in writable and str(workspace / 'evidence') in writable and '/dev' in writable, 'private writable mounts missing')
    need(set(os.listdir('/dev')) == set(devices), 'unexpected exposed device')
    for name, minor in device_numbers.items():
        info = (Path('/dev') / name).lstat()
        need(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev) == 1 and os.minor(info.st_rdev) == minor, 'guest device identity differs')
    if architecture == 'x86_64': block_service_ipc()
    else: block_service_ipc(architecture)
    return workspace


def engine(spec_path, spec_sha256):
    global TASK_DEADLINE
    spec_path = Path(spec_path)
    need(type(ENGINE_SPEC_BYTES) is bytes and hashlib.sha256(ENGINE_SPEC_BYTES).hexdigest() == spec_sha256,
         'captured engine specification required')
    spec = decode(ENGINE_SPEC_BYTES)
    need(type(spec) is dict and set(spec) == {'contract', 'seed', 'keyring', 'host_uid', 'host_namespaces', 'seed_state', 'deadline',
            'worker_source_sha256', 'runtime_source_sha256', 'worker_reference', 'runtime_reference', 'evidence_identity', 'evidence_nodes'} and
         type(spec['host_uid']) is int and 0 < spec['host_uid'] < 2**31 and
         type(spec['host_namespaces']) is dict and set(spec['host_namespaces']) == {'user', 'mnt', 'pid', 'net'} and
         all(type(v) is str and re.fullmatch(r'[a-z]+:\[[0-9]+\]', v) for v in spec['host_namespaces'].values()), 'closed engine specification required')
    need(type(EXECUTED_WORKER_SHA) is str and HEX.fullmatch(EXECUTED_WORKER_SHA) and spec['worker_source_sha256'] == EXECUTED_WORKER_SHA and
         spec['runtime_source_sha256'] == RUNTIME_SHA and type(RUNTIME_BYTES) is bytes and hashlib.sha256(RUNTIME_BYTES).hexdigest() == RUNTIME_SHA and
         type(spec['worker_reference']) is dict and set(spec['worker_reference']) == {'device', 'inode', 'size', 'sha256'} and
         spec['worker_reference']['sha256'] == EXECUTED_WORKER_SHA and
         type(spec['runtime_reference']) is dict and set(spec['runtime_reference']) == {'device', 'inode', 'size', 'sha256'} and
         spec['runtime_reference']['size'] == len(RUNTIME_BYTES) and spec['runtime_reference']['sha256'] == RUNTIME_SHA and
         type(spec['evidence_identity']) is list and len(spec['evidence_identity']) == 2 and all(type(n) is int and n >= 0 for n in spec['evidence_identity']),
         'bound worker/runtime/evidence identity required')
    need(type(spec['evidence_nodes']) is dict and set(spec['evidence_nodes']) == {'result.json', 'candidate-packages.lock'} and
         all(type(v) is list and len(v) == 2 and all(type(n) is int and n >= 0 for n in v) for v in spec['evidence_nodes'].values()),
         'bound evidence node identities required')
    contract = validate_contract(spec['contract'], spec['contract'].get('input_selection_sha256'),
                                 generic_vm_contract_sha256=spec['contract'].get('generic_vm_contract_sha256'))
    need(type(spec['deadline']) in (int, float) and math.isfinite(spec['deadline']) and
         0 < spec['deadline'] - time.monotonic() <= contract['timeout_seconds'], 'engine deadline refused')
    TASK_DEADLINE = spec['deadline']; workspace = isolate(spec)
    evidence = OWNED_OUTPUT; out = evidence.view(); result = {'status': 'FAIL', 'phase': 'isolated', 'commit_started': False,
        'committed': False, 'installed_payload_verified': False, 'hooks': 'NOT_ESTABLISHED',
        'scriptlets': 'NOT_ESTABLISHED', 'production_installation': 'NOT_ESTABLISHED', 'hardware': 'NOT RUN', 'before': {}, 'after': {},
        'auxiliary_execution': 'REFUSED_IF_PRESENT', 'worker_source_sha256': EXECUTED_WORKER_SHA,
        'runtime_source_sha256': RUNTIME_SHA, 'evidence_identity': list(evidence.identity), 'initial_evidence_nodes': spec['evidence_nodes']}
    evidence.save('result.json', result)
    root = workspace / 'system'; source = Path(spec['seed']); copied_state = copy_tree(source, root)
    need(copied_state == spec['seed_state'], 'copied baseline bytes changed')
    consumed = workspace / 'inputs'; consumed.mkdir(mode=0o700); copied_contract = json.loads(json.dumps(contract)); total = 0
    def consume(ref, filename):
        nonlocal total
        data = capture(ref); total += len(data); need(total <= MAX_INPUTS, 'consumed input byte bound')
        target = consumed / filename; target.write_bytes(data); target.chmod(0o600)
        return {'path': str(target), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    for i, row in enumerate(copied_contract['add']):
        suffix = '.pkg.tar.xz' if row['archive']['path'].endswith('.xz') else '.pkg.tar.gz'
        row['archive'] = consume(row['archive'], str(i) + suffix)
        row['signature'] = consume(row['signature'], str(i) + suffix + '.sig')
    copied_contract['keyring'] = consume(contract['keyring'], 'public-keyring'); contract = copied_contract
    mount(str(consumed), consumed, 1 << 12); mount(None, consumed, (1 << 5) | (1 << 12) | 1 | 2 | 4)
    reduce_capabilities()
    for name in ('usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'):
        need(not (root / name).exists() and not (root / name).is_symlink(), 'unaudited auxiliary executable refused')
    keys = workspace / 'gpg'; keys.mkdir(mode=0o700)
    env = environment(GNUPGHOME=str(keys), TMPDIR=str(workspace))
    runner = runtime().Runner(spec['deadline'] - time.monotonic(), env, workspace / 'logs')
    def command(argv):
        receipt = runner.run(argv, timeout=60, limit=1024**2)
        evidence.save('authentication-command.json', {'argv': argv, 'returncode': receipt.returncode,
             'merged_output': receipt.stdout.decode(errors='replace')[:8192]})
        need(receipt.returncode == 0, 'private authentication command failed'); return receipt.stdout
    alpm = None
    try:
        validate_gpg_home_path(workspace)  # Defense in the captured engine before authentication.
        gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--no-autostart', '--homedir', str(keys), '--no-auto-key-retrieve']
        command(gpg + ['--import', contract['keyring']['path']])
        public_keyring_only(command(gpg + ['--with-colons', '--list-secret-keys']), keys)
        trust = workspace / 'ownertrust'; trust.write_text(''.join(f'{row["signer"]}:6:\n' for row in contract['add']))
        command(gpg + ['--import-ownertrust', str(trust)])
        payload, ownership, accounting = {}, {}, {'nodes': 0, 'bytes': 0}
        for row in contract['add']:
            archive, signature = row['archive']['path'], row['signature']['path']
            status = command(gpg + ['--status-fd', '1', '--verify', signature, archive]).decode()
            valid = [line.split()[2:] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            need(len(valid) == 1 and len(valid[0]) == 10 and FPR.fullmatch(valid[0][0]) and valid[0][-1] == row['signer'] and valid[0][7] in {'8', '9', '10', '11'} and
                 not re.search(r'\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY)', status), 'signature signer/status refused')
            nodes = archive_payload(Path(archive), accounting); ownership[row['name']] = set(nodes)
            for name, value in nodes.items():
                need((root / name).parent.resolve().is_relative_to(root), 'existing ancestor escapes root')
                need(name not in payload or value['type'] == payload[name]['type'] == 'directory', 'archive payload overlap')
                payload[name] = value
        projected = projected_paths(tree(root), payload)
        reserve = sum(row.get('bytes', 0) for row in projected.values()) + 8 * 1024**2
        result['capacity'] = {'reserve_bytes': reserve, 'guest_free_bytes': shutil.disk_usage(workspace).free,
                              'evidence_free_bytes': shutil.disk_usage(out).free}
        need(result['capacity']['guest_free_bytes'] >= reserve and result['capacity']['evidence_free_bytes'] >= reserve, 'measured precommit capacity insufficient')
        alpm = Alpm(root, keys, out / 'alpm.log') if contract['architecture'] == 'x86_64' else Alpm(root, keys, out / 'alpm.log', 'aarch64')
        before = alpm.inventory(); result['before'] = before; result['phase'] = 'prepare'; evidence.save('result.json', result); check_inventory(before, contract['before'], 'before')
        preserved = {name: node(root / name) for name in alpm.owned_files(contract['protected'])}
        alpm.ok(alpm.alpm_trans_init(alpm.handle, FLAGS), 'transaction initialize'); alpm.started = True
        for row in contract['add']:
            package = C.c_void_p(); alpm.ok(alpm.alpm_pkg_load(alpm.handle, os.fsencode(row['archive']['path']), 1, 1, C.byref(package)), 'signed local package load')
            need(alpm.alpm_pkg_get_name(package).decode() == row['name'] and alpm.alpm_pkg_get_version(package).decode() == row['version'] and
                 alpm.alpm_pkg_get_arch(package) in (b'any', contract['architecture'].encode()), 'loaded package identity differs')
            alpm.ok(alpm.alpm_add_pkg(alpm.handle, package), 'add package')
        db = alpm.alpm_get_localdb(alpm.handle)
        for name, version in contract['remove'].items():
            package = alpm.alpm_db_get_pkg(db, name.encode()); need(package, 'remove package absent')
            need(alpm.alpm_pkg_get_version(package).decode() == version, 'remove version differs')
            alpm.ok(alpm.alpm_remove_pkg(alpm.handle, package), 'remove package')
        details = Ptr(); alpm.ok(alpm.alpm_trans_prepare(alpm.handle, C.byref(details)), 'actual prepare')
        check_prepared(alpm.packages(alpm.alpm_trans_get_add(alpm.handle)), alpm.packages(alpm.alpm_trans_get_remove(alpm.handle)),
                       {r['name']: r['version'] for r in contract['add']}, contract['remove'])
        result.update(phase='commit', commit_started=True, before=before); evidence.save('result.json', result)
        details = Ptr(); alpm.ok(alpm.alpm_trans_commit(alpm.handle, C.byref(details)), 'actual commit')
        result['committed'] = True
        alpm.close(); alpm = Alpm(root, keys, out / 'alpm.log', contract['architecture'])
        after = alpm.inventory(); result['after'] = after; check_inventory(after, contract['after'], 'after')
        for package, paths in ownership.items(): need(alpm.owned_files([package]) == paths, 'installed package ownership differs')
        for name, expected in payload.items(): need(node(root / name) == expected, 'installed payload differs: ' + name)
        for name, expected in preserved.items(): need(node(root / name) == expected, 'protected payload differs: ' + name)
        tree(root)
        copy_tree(root, out / 'system-snapshot')
        evidence.write('candidate-packages.lock', ''.join(f'{n} {v}\n' for n, v in sorted(after.items())).encode())
        result.update(status='PROVISIONAL-disposable-payload-transaction', phase='complete', installed_payload_verified=True,
                      decoded_archive_bytes=accounting['bytes'], decoded_archive_nodes=accounting['nodes'])
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        if alpm is not None: alpm.close()
        if result['status'] == 'FAIL': evidence.revoke(result)
        else: evidence.save('result.json', result)
    return int(result['status'] != 'PROVISIONAL-disposable-payload-transaction')


def database_records(root):
    local = root / 'var/lib/pacman/local'; need(local.is_dir() and not local.is_symlink(), 'export local database absent')
    packages, ownership = {}, {}
    for entry in local.iterdir():
        if entry.name == 'ALPM_DB_VERSION': continue
        need(entry.is_dir() and not entry.is_symlink() and len(packages) < MAX_PACKAGES, 'export database entry refused')
        sections = {}
        for filename in ('desc', 'files'):
            current = None
            for line in bounded_read(entry / filename).decode().splitlines():
                if line.startswith('%') and line.endswith('%'):
                    need(line not in sections, 'duplicate database section'); sections[line] = []; current = line
                elif line:
                    need(current is not None, 'database section absent'); sections[current].append(line)
        need(len(sections.get('%NAME%', [])) == len(sections.get('%VERSION%', [])) == 1 and '%FILES%' in sections, 'export package metadata incomplete')
        name, version = sections['%NAME%'][0], sections['%VERSION%'][0]; package_map({name: version})
        need(name not in packages, 'export duplicate package')
        packages[name] = version
        ownership[name] = {relative(n.rstrip('/')) for n in sections['%FILES%']}
    return packages, ownership


def validate_export(output, contract, copied, seed, result):
    tick(); need(isinstance(output, Evidence), 'retained evidence required'); output.check()
    fd = os.open('system-snapshot', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=output.fd)
    try:
        info = os.fstat(fd); need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'export root ownership refused')
        lock = validate_export_tree(Path('/proc/self/fd/' + str(fd)), output, contract, copied, seed, result)
        output.check(); return lock
    finally: os.close(fd)


def validate_export_tree(exported, output, contract, copied, seed, result):
    rows = tree(exported)
    need(all(v['uid'] == os.getuid() and v['gid'] == os.getgid() for v in rows.values()), 'export ownership outside mapping')
    check_inventory(result.get('before'), contract['before'], 'receipt before')
    check_inventory(result.get('after'), contract['after'], 'receipt after')
    need(result.get('commit_started') is True and result.get('committed') is True and result.get('installed_payload_verified') is True and result.get('phase') == 'complete', 'incomplete provisional receipt')
    expected_lock = ''.join(f'{n} {v}\n' for n, v in sorted(contract['after'].items())).encode()
    need(output.read('candidate-packages.lock', 65536) == expected_lock, 'export package lock differs')
    actual, ownership = database_records(exported); check_inventory(actual, contract['after'], 'export database')
    payload, accounting = {}, {'nodes': 0, 'bytes': 0}
    for row in copied['add']:
        nodes = archive_payload(capture(row['archive']), accounting)
        need(ownership.get(row['name']) == set(nodes), 'export package ownership differs')
        payload.update(nodes)
    for name, expected in payload.items():
        actual_node = dict(rows.get(name, {})); actual_node.update(uid=0, gid=0)
        need(actual_node == expected, 'export payload differs: ' + name)
    if contract['protected']:
        before, owned_before = database_records(seed); check_inventory(before, contract['before'], 'seed database')
        for name in contract['protected']:
            need(ownership.get(name) == owned_before.get(name), 'export protected ownership differs')
            for path in owned_before[name]: need(rows.get(path) == node(seed / path), 'export protected payload differs')
    # Every exported node is bounded and safe; the local DB is checked independently.
    result['export_tree_sha256'] = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
    return expected_lock


def execute(contract_path, contract_sha256, output_path, *, worker_source_sha256=None, selection_sha256=None, allow=False,
            generic_vm_contract=None, generic_vm_contract_sha256=None):
    global TASK_DEADLINE, OWNED_OUTPUT, ENGINE_STARTED, OWNED_CAPSULES
    need(OWNED_CAPSULES is None or not OWNED_CAPSULES.owned, 'owned source capsules pending disposal')
    if isinstance(OWNED_OUTPUT, Evidence): OWNED_OUTPUT.close()
    OWNED_OUTPUT = None; ENGINE_STARTED = False
    started = time.monotonic(); TASK_DEADLINE = None
    need(allow and os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, 'ordinary explicit parent required')
    need(type(worker_source_sha256) is str and HEX.fullmatch(worker_source_sha256), 'independently reviewed worker source pin required')
    worker_path = Path(__file__).absolute()
    worker_bytes = capture({'path': str(worker_path), 'size': worker_path.stat().st_size, 'sha256': worker_source_sha256}, 128 * 1024)
    contract_path = Path(contract_path); raw = capture({'path': str(contract_path.absolute()), 'size': contract_path.stat().st_size, 'sha256': contract_sha256}, 1024**2)
    need((generic_vm_contract is None) == (generic_vm_contract_sha256 is None), 'complete generic fixture selection required')
    contract = validate_contract(decode(raw), selection_sha256, generic_vm_contract_sha256=generic_vm_contract_sha256); TASK_DEADLINE = started + contract['timeout_seconds']; tick()
    if contract['scope'] == GENERIC_SCOPE:
        generic_preflight(generic_vm_contract, generic_vm_contract_sha256, worker_source_sha256)
    elif contract['architecture']=='aarch64':native_authority(selection_sha256,worker_source_sha256)
    workspace = private(contract['workspace'], os.getuid())
    output = Path(output_path); need(output == workspace / 'evidence' and not output.exists() and not output.is_symlink(), 'new fixed evidence output required')
    result = {'status': 'FAIL', 'phase': 'snapshot', 'commit_started': False, 'committed': False,
              'worker_source_sha256': worker_source_sha256, 'runtime_source_sha256': RUNTIME_SHA}
    scratch = None; capsules = SourceCapsules(); OWNED_CAPSULES = capsules; rt = runtime()
    try:
        with custody_guard(check_terminal), capsules.cleanup_scope():
            output.mkdir(mode=0o700); OWNED_OUTPUT = Evidence(output); evidence = OWNED_OUTPUT
            result['evidence_identity'] = list(evidence.identity); evidence.save('result.json', result)
            evidence.write('candidate-packages.lock', b'', exclusive=True)
            validate_gpg_home_path(workspace)  # Before seed copying or any worker launch.
            scratch = Path(tempfile.mkdtemp(prefix='.local-transaction-', dir=workspace.parent)); scratch.chmod(0o700)
            seed = workspace / 'system'; seed.mkdir(mode=0o700, exist_ok=True); private(seed, os.getuid())
            need(all(v['uid'] == os.getuid() and v['gid'] == os.getgid() for v in tree(seed).values()), 'seed ownership outside namespace mapping')
            seed_state = copy_tree(seed, scratch / 'seed')
            for value in seed_state.values(): value.update(uid=0, gid=0)
            copied = json.loads(json.dumps(contract)); inputs = scratch / 'inputs'; inputs.mkdir(mode=0o700); total = 0
            worker_copy, runtime_copy = inputs / 'worker.py', inputs / 'runtime.py'
            worker_copy.write_bytes(worker_bytes); worker_copy.chmod(0o400)
            runtime_copy.write_bytes(RUNTIME_BYTES); runtime_copy.chmod(0o400)
            worker_fd = sealed_source(worker_bytes, 'local-transaction-worker', registry=capsules)
            runtime_fd = sealed_source(RUNTIME_BYTES, 'local-transaction-runtime', registry=capsules)
            worker_ref, runtime_ref = source_reference(worker_fd, worker_source_sha256), source_reference(runtime_fd, RUNTIME_SHA)
            def snapshot(ref, name):
                nonlocal total
                data = capture(ref); total += len(data); need(total <= MAX_INPUTS, 'aggregate input bytes exceeded')
                target = inputs / name; target.write_bytes(data); target.chmod(0o600)
                return {'path': str(target), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            for i, row in enumerate(copied['add']):
                suffix = '.pkg.tar.xz' if row['archive']['path'].endswith('.xz') else '.pkg.tar.gz'
                row['archive'] = snapshot(row['archive'], str(i) + suffix)
                row['signature'] = snapshot(row['signature'], str(i) + suffix + '.sig')
            keyring = snapshot(copied['keyring'], 'public-keyring'); copied['keyring'] = keyring
            spec = {'contract': copied, 'seed': str(scratch / 'seed'), 'keyring': keyring['path'],
                    'host_uid': os.getuid(), 'host_namespaces': namespaces(), 'seed_state': seed_state, 'deadline': TASK_DEADLINE,
                    'worker_source_sha256': worker_source_sha256, 'runtime_source_sha256': RUNTIME_SHA,
                    'worker_reference': worker_ref, 'runtime_reference': runtime_ref,
                    'evidence_identity': list(evidence.identity),
                    'evidence_nodes': {name: evidence.node_identity(name) for name in ('result.json', 'candidate-packages.lock')}}
            save(inputs / 'engine.json', spec); (inputs / 'engine.json').chmod(0o400); spec_sha = digest(inputs / 'engine.json')
            env = environment(TMPDIR=str(scratch))
            child = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--mount-proc', '--net', '--fork', '--kill-child=SIGKILL', '--',
                     '/usr/bin/python3', '-I', '-B', '-c', CHILD_LOADER, 'WORKER_FD', worker_source_sha256, str(inputs / 'engine.json'), spec_sha,
                     'EVIDENCE_FD', 'RUNTIME_FD', RUNTIME_SHA]
            argv = ['/usr/bin/python3', '-I', '-B', '-c', OUTER_LOADER, str(os.getpid()), str(evidence.fd),
                    str(evidence.identity[0]), str(evidence.identity[1]), str(worker_fd), str(worker_ref['device']), str(worker_ref['inode']),
                    str(runtime_fd), str(runtime_ref['device']), str(runtime_ref['inode']), *child]
            ENGINE_STARTED = True
            evidence.check()
            completed = supervise(argv, TASK_DEADLINE - time.monotonic(), env, scratch / 'supervisor-logs')
            evidence.write('supervisor-command.log', bounded_read(scratch / 'supervisor-logs/command.log'), exclusive=True)
            tick(); evidence.check(); result = read_result(evidence)
            need(completed.returncode == 0 and result['status'] == 'PROVISIONAL-disposable-payload-transaction', 'guarded engine did not complete')
            need(result.get('worker_source_sha256') == worker_source_sha256 and result.get('runtime_source_sha256') == RUNTIME_SHA and
                 result.get('evidence_identity') == list(evidence.identity), 'engine receipt execution identity differs')
            lock = validate_export(evidence, contract, copied, scratch / 'seed', result)
            shutil.rmtree(scratch); scratch = None; tick()
            # Promotion is revocable and still protected from ordinary soft termination.
            tick(); evidence.check(); evidence.write('installed-packages.lock', lock, exclusive=True)
            evidence.unlink('candidate-packages.lock')
            result.update(status='PASS-disposable-payload-transaction', parent_export_verified=True)
            tick(); evidence.save('result.json', result)
        return result
    except BaseException as error:
        if OWNED_OUTPUT is None: raise
        evidence = OWNED_OUTPUT
        # Revoke authority first, without consulting an expired work deadline.
        for name in ('installed-packages.lock', 'candidate-packages.lock'):
            if name in evidence.nodes: evidence.overwrite(name, b'REVOKED\n')
            evidence.unlink(name, checked=False)
        try: result = read_result(evidence, checked=False)
        except Exception: result = {'phase': 'unknown', 'commit_started': 'UNKNOWN', 'committed': 'UNKNOWN'}
        result.update(status='FAIL', parent_error_type=type(error).__name__, parent_error=str(error)[:512])
        result['capsule_cleanup'] = capsules.last_report
        if 'error' not in result: result.update(error_type=type(error).__name__, error=str(error)[:512])
        evidence.revoke(result)
        if scratch is not None:
            try: evidence.write('supervisor-command.log', bounded_read(scratch / 'supervisor-logs/command.log'), exclusive=True, checked=False)
            except (OSError, ValueError): pass
        return result
    finally:
        if scratch is not None: shutil.rmtree(scratch)


def cli_failure(error):
    record = {'status': 'REFUSED', 'commit_started': False, 'committed': False, 'output': None}
    if type(error) is GenericDeclaredAfterMismatch: record['phase'] = 'declaration-after'
    if isinstance(OWNED_OUTPUT, Evidence) and OWNED_OUTPUT.fd is not None:
        record.update(status='FAIL', commit_started='UNKNOWN' if ENGINE_STARTED else False,
                      committed='UNKNOWN' if ENGINE_STARTED else False, output=str(OWNED_OUTPUT), evidence_identity=list(OWNED_OUTPUT.identity))
        with runtime().defer_signals():
            try:
                receipt = read_result(OWNED_OUTPUT, checked=False)
                record.update({k: receipt[k] for k in ('commit_started', 'committed') if k in receipt})
            except BaseException: pass
            OWNED_OUTPUT.revoke(record | {'parent_error': str(error)[:512]})
    return record


def dispose_terminal():
    """Retain one revocation loan through close and signal-handler restoration.

    Callable main leaves that bounded loan for caller disposal, the next call,
    or kernel process teardown. No revocation is promised after its last FD closes.
    Retaining a loan does not keep cancellation handlers installed after main returns.
    """
    global OWNED_OUTPUT
    if not isinstance(OWNED_OUTPUT, Evidence) or OWNED_OUTPUT.fd is None: return
    original = OWNED_OUTPUT
    try:
        with runtime().defer_signals() as deferred:
            OWNED_OUTPUT = original.duplicate()
            original.close()
        if deferred: raise runtime().Cancelled(deferred[0])
    except BaseException as error:
        cli_failure(error)  # Loan remains open even if originals were partly/all closed.
        with runtime().defer_signals(): original.close()
        raise


def publish_terminal(record):
    # Do not defer a buffered-output failure to interpreter shutdown.
    print(json.dumps(record, sort_keys=True), flush=True)
    sys.stdout.flush()


def check_terminal():
    OWNED_OUTPUT.check(); OWNED_OUTPUT.check_node('result.json'); OWNED_OUTPUT.check_node('installed-packages.lock')


def fail_terminal(error):
    with runtime().cancellation_handlers():
        record = cli_failure(error)
        try: publish_terminal(record)
        except BaseException as publication_error: cli_failure(publication_error)
    return 2


def main():
    global OWNED_OUTPUT, ENGINE_STARTED
    if isinstance(OWNED_OUTPUT, Evidence): OWNED_OUTPUT.close()
    OWNED_OUTPUT = None; ENGINE_STARTED = False
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', type=Path, help=argparse.SUPPRESS); parser.add_argument('--engine-sha256', help=argparse.SUPPRESS)
    parser.add_argument('--contract', type=Path); parser.add_argument('--contract-sha256'); parser.add_argument('--output', type=Path)
    parser.add_argument('--worker-source-sha256')
    parser.add_argument('--generic-vm-contract', type=Path); parser.add_argument('--generic-vm-contract-sha256')
    parser.add_argument('--selection-sha256'); parser.add_argument('--allow-disposable-payload-commit', action='store_true')
    args = parser.parse_args()
    if args.engine is not None:
        need(type(args.engine_sha256) is str and HEX.fullmatch(args.engine_sha256), 'independent engine specification pin required')
        need(args.worker_source_sha256 == EXECUTED_WORKER_SHA and EXECUTED_WORKER_SHA is not None, 'captured worker launch required')
        return engine(args.engine, args.engine_sha256)
    try:
        code = 2
        with custody_guard(lambda: check_terminal() if code == 0 else None):
            try:
                need(all((args.contract, args.contract_sha256, args.output, args.worker_source_sha256)), 'complete CLI arguments required')
                result = execute(args.contract, args.contract_sha256, args.output, selection_sha256=args.selection_sha256,
                                 worker_source_sha256=args.worker_source_sha256, allow=args.allow_disposable_payload_commit,
                                 generic_vm_contract=args.generic_vm_contract, generic_vm_contract_sha256=args.generic_vm_contract_sha256)
                accepted = result['status'] == 'PASS-disposable-payload-transaction'
                if accepted: check_terminal()
                publish_terminal({'status': result['status'], 'output': str(args.output)})
                if accepted: check_terminal()
                code = int(not accepted)
            except BaseException as error:
                code = fail_terminal(error)  # Revoke before ending cancellation protection.
            finally:
                dispose_terminal()
        # The loan remains available if restoration itself delivered a cancellation.
        return code
    except BaseException as error:
        return fail_terminal(error)


if __name__ == '__main__': raise SystemExit(main())
