#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite synthetic-preview controller. No runtime actor backend is shipped."""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import sys
import time
import zlib

TOTAL, CLEANUP, CONSUMER, ACTOR, LINK = 60, 10, 20, 30, 5
LOG_LIMIT, FRAME_LIMIT = 1024**2, 2 * 1024**2
ROLES = ('daemon', 'producer', 'consumer', 'link')
GRANTS = ('dependency_closure', 'installed_ledger', 'licenses', 'executables',
          'plugins', 'libraries', 'daemon_config', 'source', 'isolation', 'backend')
EOS = re.compile(rb'^Got EOS from element "[A-Za-z0-9_.-]{1,64}"\.$', re.M)
FORCED = (b'handling interrupt.', b'Interrupt: Stopping pipeline',
          b'Interrupt while waiting for EOS', b'Forcing EOS on the pipeline', b'ERROR:')
CAPS = 'video/x-raw,format=RGB,width=160,height=120,framerate=10/1'
REASONS = {'ADMISSION_UNAVAILABLE', 'INVALID_INPUT', 'START_UNKNOWN', 'GRAPH_REFUSED',
           'ACTOR_EXIT', 'LINK_EXIT', 'CONSUMER_EXIT', 'NATURAL_EOS_UNOBSERVED',
           'OUTPUT_BOUND', 'FRAME_REFUSED', 'DEADLINE', 'CANCELLED', 'BACKEND_ERROR', 'CLEANUP_FAILED'}


class Refused(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'BACKEND_ERROR'
        super().__init__(self.reason)


def need(ok, reason='INVALID_INPUT'):
    if not ok: raise Refused(reason)


def digest(data): return hashlib.sha256(data).hexdigest()


def command_plan(nonce):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce))
    source, sink = 'caa-camera-source.' + nonce, 'caa-camera-preview.' + nonce
    properties = lambda name, kind: ('stream-properties=props,node.name=(string)' + name +
                                    ',media.class=(string)' + kind + ',media.role=(string)Camera')
    return {
        'daemon': ['/usr/bin/pipewire', '-c', 'PRIVATE/config/camera.conf'],
        'producer': ['/usr/bin/gst-launch-1.0', '-e', 'videotestsrc', 'is-live=true',
            'num-buffers=250', 'pattern=smpte', '!', CAPS, '!', 'pipewiresink', 'mode=provide',
            properties(source, 'Video/Source')],
        'consumer': ['/usr/bin/gst-launch-1.0', '-e', 'pipewiresrc', 'autoconnect=false',
            'target-object=' + source, 'num-buffers=1', properties(sink, 'Stream/Input/Video'),
            '!', CAPS, '!', 'pngenc', 'snapshot=true', '!', 'filesink', 'location=PRIVATE/preview.png'],
        'link': ['/usr/bin/pw-link', '--remote=caa-camera.' + nonce, '--wait', 'SOURCE_PORT', 'SINK_PORT']}


def environment(private, nonce):
    # These are integration requirements, not proof that these directories/files exist.
    p = str(private)
    return {'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': p + '/home',
        'XDG_RUNTIME_DIR': p + '/runtime', 'PIPEWIRE_RUNTIME_DIR': p + '/runtime',
        'PIPEWIRE_REMOTE': 'caa-camera.' + nonce, 'XDG_CACHE_HOME': p + '/cache',
        'XDG_CONFIG_HOME': p + '/config', 'GST_REGISTRY_1_0': p + '/cache/registry.bin',
        'GST_PLUGIN_PATH_1_0': '', 'GST_PLUGIN_SYSTEM_PATH_1_0': p + '/plugins',
        'GST_PLUGIN_SCANNER_1_0': p + '/tools/gst-plugin-scanner', 'GST_DEBUG': '0'}


@dataclass(frozen=True)
class Admission:
    """Created by independently reviewed backend preflight, never from caller JSON."""
    uid: int
    gid: int
    pins: tuple

    def validate(self):
        need(type(self.uid) is int and type(self.gid) is int and self.uid == os.getuid() and
             self.gid == os.getgid() and self.uid == os.geteuid() != 0 and self.gid == os.getegid() != 0)
        need(type(self.pins) is tuple and len(self.pins) == len(GRANTS))
        for row in self.pins:
            need(type(row) is tuple and len(row) == 2)
            name, pin = row
            need(type(name) is str and name in GRANTS and type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin))
        need(tuple(name for name, _ in self.pins) == GRANTS)


@dataclass(frozen=True)
class Observation:
    alive: bool
    code: object
    reaped: bool
    stdout: bytes = b''
    stderr: bytes = b''
    launch: str = 'PID_OBSERVED'

    # reaped covers the entire owned tree, not merely a returned leader PID.
    def lifecycle(self):
        need(type(self.launch) is str and self.launch in ('PID_OBSERVED','NO_LAUNCH','UNOBSERVED'))
        if self.launch == 'NO_LAUNCH':
            need(self.alive is False and self.code is None and self.reaped is True)
        elif self.launch == 'UNOBSERVED':
            need(self.alive is None and self.code is None and self.reaped is False)
        else:
            need(type(self.alive) is bool and type(self.reaped) is bool)
            need((self.alive and self.code is None and not self.reaped) or
                 (not self.alive and type(self.code) is int and -64 <= self.code <= 255))
        return self

    def validate(self):
        self.lifecycle()
        need(type(self.stdout) is bytes and type(self.stderr) is bytes)
        need(len(self.stdout) <= LOG_LIMIT and len(self.stderr) <= LOG_LIMIT, 'OUTPUT_BOUND')
        return self


class Backend:
    """Integration interface; every method is bounded by its absolute deadline.

    admit/verify must authenticate installed closure and independently enforced isolation;
    metadata assertions are insufficient. reserve/start journal owned launch before exec.
    observe reports cumulative bounded logs and actual returned exits. reap must verify the
    entire reserved owned process tree, including scanner children and ambiguous starts.
    registry is a private source-bound projection of the owned native-protocol graph.
    No actual process/device/plugin/namespace adapter exists in this source phase.
    """
    origin = 'UNAVAILABLE'
    def admit(self, private, nonce, plan_sha256, deadline): raise Refused('ADMISSION_UNAVAILABLE')
    def verify(self, admission, deadline): raise Refused('ADMISSION_UNAVAILABLE')
    def reserve(self, role, deadline): raise NotImplementedError
    def start(self, role, argv, env, deadline): raise NotImplementedError
    def observe(self, role, deadline): raise NotImplementedError
    def pid(self, role): raise NotImplementedError
    def registry(self, deadline): raise NotImplementedError
    def stop(self, role, number, deadline): raise NotImplementedError
    def reap(self, role, deadline): raise NotImplementedError


class RuntimeAuthority:
    """Coordinator-supplied, source-pinned verifier; no concrete grant is shipped.

    Checks accepted ledger/signature/license closure, every executable/plugin/library,
    the backend source itself, and live caller-owned namespace/runtime containment.
    verify rechecks the same identities before operations and after cleanup. A backend's
    own metadata/pins/origin string can never supply this independent authority.
    """
    def admit(self, backend, private, nonce, plan_sha256, deadline):
        raise Refused('ADMISSION_UNAVAILABLE')
    def verify(self, backend, admission, deadline):
        raise Refused('ADMISSION_UNAVAILABLE')


@contextmanager
def cancellation(events=None):
    events = [] if events is None else events
    numbers = {signal.SIGINT, signal.SIGTERM}
    def record(number, _):
        if len(events) < 16: events.append(number)
    previous = {n: signal.getsignal(n) for n in (signal.SIGINT, signal.SIGTERM)}
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, numbers)
    try:
        for n in previous: signal.signal(n, record)
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
        yield events
    finally:
        active, failure = sys.exc_info()[1], None
        def restore(action):
            nonlocal failure
            for attempt in range(2):
                try: action(); return
                except BaseException as error:
                    if failure is None: failure = error
                    if isinstance(error, (KeyboardInterrupt, SystemExit)):
                        record(None, None)  # API control, not an invented delivered signal.
                        if attempt == 0: continue
                    return
        restore(lambda: signal.pthread_sigmask(signal.SIG_BLOCK, numbers))
        for n, handler in previous.items():
            restore(lambda n=n, handler=handler: signal.signal(n, handler))
        # Standard signals coalesce; inspect/drain each once, with no blocking wait.
        # Preserve a caller's originally blocked signals instead of consuming them.
        for n in previous:
            def pending(n=n):
                if n in signal.sigpending():
                    record(n, None)
                    if n not in original_mask: signal.sigtimedwait({n}, 0)
            restore(pending)
        restore(lambda: need(all(signal.getsignal(n) == handler for n, handler in previous.items()), 'BACKEND_ERROR'))
        restore(lambda: signal.pthread_sigmask(signal.SIG_SETMASK, original_mask))
        if failure is not None and active is None: raise failure


def natural_eos(row):
    row.validate()
    return not row.alive and row.code == 0 and bool(EOS.search(row.stdout)) and not any(
        token in row.stdout or token in row.stderr for token in FORCED)


def exit_record(code):
    return {'kind': 'UNOBSERVED' if code is None else 'EXIT_SIGNAL' if code < 0 else
            'EXIT_NONZERO' if code else 'EXIT_ZERO', 'code': code}


def png(data):
    """One bounded noninterlaced RGB8 PNG; CRCs, full zlib extent and scanlines checked."""
    need(type(data) is bytes and 0 < len(data) <= FRAME_LIMIT and data[:8] == b'\x89PNG\r\n\x1a\n', 'FRAME_REFUSED')
    at, count, compressed, state = 8, 0, bytearray(), 'HEADER'
    while at < len(data):
        need(at + 12 <= len(data) and count < 128, 'FRAME_REFUSED')
        size, kind = struct.unpack('>I4s', data[at:at + 8]); end = at + 12 + size
        need(end <= len(data), 'FRAME_REFUSED')
        body = data[at + 8:end - 4]
        need(zlib.crc32(kind + body) & 0xffffffff == struct.unpack('>I', data[end - 4:end])[0], 'FRAME_REFUSED')
        if state == 'HEADER':
            need(kind == b'IHDR' and size == 13 and struct.unpack('>IIBBBBB', body) ==
                 (160, 120, 8, 2, 0, 0, 0), 'FRAME_REFUSED'); state = 'DATA'
        elif kind == b'IDAT' and state == 'DATA': compressed.extend(body)
        elif kind == b'IEND':
            need(state == 'DATA' and size == 0 and end == len(data) and compressed, 'FRAME_REFUSED')
            state = 'END'
        else: raise Refused('FRAME_REFUSED')
        at, count = end, count + 1
    need(state == 'END', 'FRAME_REFUSED')
    try:
        decoder = zlib.decompressobj(); pixels = decoder.decompress(compressed, 120 * 481 + 1)
        need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and
             len(pixels) == 120 * 481 and all(pixels[n * 481] <= 4 for n in range(120)), 'FRAME_REFUSED')
    except zlib.error as error: raise Refused('FRAME_REFUSED') from error
    return {'sha256': digest(data), 'bytes': len(data), 'width': 160, 'height': 120, 'format': 'RGB8'}


def private_directory(path):
    path = Path(path)
    need(re.fullmatch(r'[A-Za-z0-9/_@.+-]{1,1024}',str(path)) and len(path.parts)<=64 and
         path.is_absolute() and path == path.resolve() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)) and
         not any(path == Path(x) or path.is_relative_to(x) for x in ('/dev', '/proc', '/sys')))
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return path, info


def capture(private, name):
    allowed = {'preview.png':FRAME_LIMIT,'registry.json':LOG_LIMIT} | {
        role+'.'+stream+'.log':LOG_LIMIT for role in ROLES for stream in ('stdout','stderr')}
    need(type(name) is str and name in allowed)
    limit = allowed[name]
    path, before = private_directory(private)
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit, 'FRAME_REFUSED')
            def read():
                data=bytearray()
                while len(data)<=limit:
                    block=os.read(fd,min(65536,limit+1-len(data)))
                    if not block:break
                    data.extend(block)
                return bytes(data)
            data = read()
            os.lseek(fd, 0, os.SEEK_SET); second = read()
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            identity = lambda s: (s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(identity(info) == identity(os.fstat(fd)) == identity(current) and data == second and
                 len(data) == info.st_size, 'FRAME_REFUSED')
            _, after = private_directory(private)
            need((before.st_dev,before.st_ino) == (os.fstat(directory).st_dev,os.fstat(directory).st_ino) ==
                 (after.st_dev,after.st_ino), 'FRAME_REFUSED')
            return data
        finally: os.close(fd)
    finally: os.close(directory)


def frame(private): return png(capture(private,'preview.png'))


def ports(data, nonce, producer_pid, consumer_pid):
    need(type(data) is bytes and len(data) <= LOG_LIMIT, 'OUTPUT_BOUND')
    def unique(pairs):
        result = {}
        for k,v in pairs:
            need(k not in result, 'GRAPH_REFUSED'); result[k] = v
        return result
    try: rows = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error: raise Refused('GRAPH_REFUSED') from error
    need(type(rows) is dict and set(rows) == {'nodes','ports'} and type(rows['nodes']) is list and
         type(rows['ports']) is list and len(rows['nodes']) == len(rows['ports']) == 2, 'GRAPH_REFUSED')
    nodes = []
    for row, name, pid in zip(rows['nodes'], ('caa-camera-source.', 'caa-camera-preview.'), (producer_pid,consumer_pid)):
        need(type(pid) is int and 0 < pid < 2**31 and type(row) is dict and set(row) == {'id','name','pid'} and
             type(row['id']) is int and 0 < row['id'] < 2**32 and row['name'] == name + nonce and
             type(row['pid']) is int and row['pid'] == pid, 'GRAPH_REFUSED'); nodes.append(row['id'])
    ids = []
    for row, node, direction in zip(rows['ports'],nodes,('out','in')):
        need(type(row) is dict and set(row) == {'id','node','direction'} and type(row['id']) is int and
             0 < row['id'] < 2**32 and type(row['node']) is int and row['node'] == node and
             row['direction'] == direction, 'GRAPH_REFUSED'); ids.append(row['id'])
    need(nodes[0] != nodes[1] and ids[0] != ids[1] and producer_pid != consumer_pid, 'GRAPH_REFUSED')
    return ids


def supervise(backend, private, nonce, authority=None):
    """Run only through an independently reviewed backend; caller JSON cannot select one."""
    plan = command_plan(nonce); private, _ = private_directory(private)
    need(len((str(private)+'/runtime/caa-camera.'+nonce).encode())<108)
    origin = backend.origin
    need(type(origin) is str and origin in ('UNAVAILABLE','CONTROLLED_FIXTURE','VERIFIED_SOFTWARE_RUNTIME'))
    started = time.monotonic(); end = started + TOTAL; cutoff = end - CLEANUP
    result = {'schema_version':1, 'status':'FAIL', 'origin':origin, 'first_failure':'NONE',
        'software_transport':'NOT RUN', 'physical_camera':'NOT RUN', 'hardware':'NOT RUN',
        'display_preview':'NOT RUN', 'performance':'NOT MEASURED', 'device_access':False, 'public_frame_export':False, 'cancelled':False, 'cleanup_failure':'NONE', 'frame':None, 'cleanup':'NOT_RUN',
        'graph_sha256':None, 'grant_pins':None, 'plan_sha256':digest(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()),
        'actors':{r:{'launch':'NOT_ATTEMPTED','exit':exit_record(None),'exit_origin':'UNOBSERVED',
                      'natural_eos':False,'reaped':False,'cleanup_requests':[]} for r in ROLES}}
    reserved, deadlines, finished, admitted, complete = [], {}, {}, None, False
    def fail(reason):
        if reason == 'CANCELLED': result['cancelled'] = True
        if result['first_failure'] == 'NONE': result['first_failure'] = reason
    def observe(role, deadline, strict=True):
        row = backend.observe(role, deadline)
        need(type(row) is Observation); row.lifecycle(); public = result['actors'][role]
        need(not public['reaped'] or row.reaped, 'INVALID_INPUT')
        previous=public['exit']['code']
        need(previous is None or row.code == previous, 'INVALID_INPUT')
        public.update(exit=exit_record(row.code), reaped=row.reaped)
        if row.launch == 'NO_LAUNCH': public['launch'] = 'NO_LAUNCH'
        if not row.alive and row.code is not None and public['exit_origin'] == 'UNOBSERVED':
            finished[role] = time.monotonic()
            public.update(exit_origin='PRE_STOP_RETURN' if not public['cleanup_requests'] else 'CLEANUP')
        if strict:
            row.validate()
            if origin == 'VERIFIED_SOFTWARE_RUNTIME' and not row.alive:
                need(row.stdout == capture(private,role+'.stdout.log') and
                     row.stderr == capture(private,role+'.stderr.log'), 'OUTPUT_BOUND')
            if role in ('producer','consumer') and not public['cleanup_requests']:
                public['natural_eos'] = natural_eos(row)
        return row
    def start(role, argv):
        reserved.append(role); result['actors'][role]['launch'] = 'UNKNOWN'
        deadlines[role] = min(cutoff,time.monotonic() + (CONSUMER if role == 'consumer' else LINK if role == 'link' else ACTOR))
        try:
            backend.reserve(role,deadlines[role]); backend.start(role,argv,environment(private,nonce),deadlines[role])
            pid = backend.pid(role)
            need(type(pid) is int and 0 < pid < 2**31, 'START_UNKNOWN')
            result['actors'][role]['launch'] = 'PID_OBSERVED'
        except Refused: raise
        except Exception as error: raise Refused('START_UNKNOWN') from error
    def verify(deadline):
        if origin != 'CONTROLLED_FIXTURE':
            need(isinstance(authority, RuntimeAuthority), 'ADMISSION_UNAVAILABLE')
            authority.verify(backend,admitted,deadline)
        backend.verify(admitted,deadline)
        need(backend.origin == origin)
    def check(events):
        need(not events, 'CANCELLED'); need(time.monotonic() < cutoff, 'DEADLINE')
        verify(cutoff)
        for role in reserved:
            row = observe(role, cutoff)
            need(row.launch == 'PID_OBSERVED', 'START_UNKNOWN')
            need((time.monotonic() if row.alive else finished[role]) < deadlines[role], 'DEADLINE')
            if role == 'daemon': need(row.alive, 'ACTOR_EXIT')
            if role == 'producer':
                need(row.alive or natural_eos(row), 'ACTOR_EXIT')
                if 'link' not in reserved: need(row.alive, 'GRAPH_REFUSED')
            if role == 'consumer' and 'link' not in reserved:
                need(row.alive or row.code == 0, 'CONSUMER_EXIT')
                need(row.alive, 'GRAPH_REFUSED')
    events = []
    try:
        with cancellation(events):
            try:
                need(backend.origin == origin)
                need(not events, 'CANCELLED')
                if origin == 'VERIFIED_SOFTWARE_RUNTIME':
                    need(isinstance(authority,RuntimeAuthority), 'ADMISSION_UNAVAILABLE')
                    admitted=authority.admit(backend,private,nonce,result['plan_sha256'],cutoff)
                else:
                    admitted=backend.admit(private,nonce,result['plan_sha256'],cutoff)
                need(type(admitted) is Admission); admitted.validate()
                result['grant_pins'] = dict(admitted.pins)
                need(origin in ('CONTROLLED_FIXTURE','VERIFIED_SOFTWARE_RUNTIME'))
                for role in ('daemon','producer','consumer'):
                    check(events)
                    if role == 'consumer':
                        need(not (private/'preview.png').exists() and not (private/'preview.png').is_symlink(), 'FRAME_REFUSED')
                    start(role,[arg.replace('PRIVATE',str(private)) for arg in plan[role]])
                check(events)
                graph = backend.registry(cutoff)
                if origin == 'VERIFIED_SOFTWARE_RUNTIME':
                    need(graph == capture(private,'registry.json'), 'GRAPH_REFUSED')
                selected = ports(graph,nonce,backend.pid('producer'),backend.pid('consumer'))
                result['graph_sha256'] = digest(graph)
                check(events); start('link',plan['link'][:-2]+list(map(str,selected)))
                while True:
                    check(events); consumer, link = observe('consumer',cutoff), observe('link',cutoff)
                    need(link.alive or link.code == 0, 'LINK_EXIT')
                    need(consumer.alive or consumer.code == 0, 'CONSUMER_EXIT')
                    if not consumer.alive and not link.alive:
                        need(natural_eos(consumer), 'NATURAL_EOS_UNOBSERVED')
                        result['frame'] = frame(private); complete = True; break
                    time.sleep(.01)
            except Refused as error: fail(error.reason)
            except (KeyboardInterrupt, SystemExit): fail('CANCELLED')
            except Exception: fail('BACKEND_ERROR')
            finally:
                cleanup_ok = True
                def cleanup_fail(reason, error=None):
                    if isinstance(error, (KeyboardInterrupt, SystemExit)): fail('CANCELLED')
                    if result['cleanup_failure'] == 'NONE': result['cleanup_failure'] = reason
                teardown = min(end,time.monotonic()+CLEANUP)
                # Log/schema failure must never skip an owned reservation's teardown.
                def stop(role, number, label):
                    result['actors'][role]['cleanup_requests'].append(label)
                    backend.stop(role,number,teardown)
                for role in reversed(reserved):
                    needs_stop = True
                    try:
                        state=observe(role,teardown,False)
                        needs_stop = state.alive is not False or not state.reaped
                    except BaseException as error: cleanup_ok=False; cleanup_fail('OBSERVATION_FAILED', error)
                    if needs_stop:
                        try: stop(role,signal.SIGTERM,'TERM')
                        except BaseException as error: cleanup_ok=False; cleanup_fail('STOP_FAILED', error)
                gentle = min(teardown,time.monotonic()+2)
                while time.monotonic() < gentle:
                    try:
                        states=[observe(role,teardown,False) for role in reserved]
                        if all(row.alive is False and row.reaped for row in states): break
                    except BaseException as error: cleanup_ok=False; cleanup_fail('OBSERVATION_FAILED', error); break
                    try: time.sleep(.01)
                    except (KeyboardInterrupt, SystemExit) as error:
                        cleanup_ok=False; cleanup_fail('OBSERVATION_FAILED', error); break
                for role in reversed(reserved):
                    needs_stop = True
                    try:
                        state=observe(role,teardown,False)
                        needs_stop = state.alive is not False or not state.reaped
                    except BaseException as error: cleanup_ok=False; cleanup_fail('OBSERVATION_FAILED', error)
                    if needs_stop:
                        try: stop(role,signal.SIGKILL,'KILL')
                        except BaseException as error: cleanup_ok=False; cleanup_fail('STOP_FAILED', error)
                    try:
                        backend.reap(role,teardown); row=observe(role,teardown,False)
                        if row.alive is not False or not row.reaped:
                            cleanup_ok=False; cleanup_fail('ABSENCE_UNVERIFIED')
                    except BaseException as error: cleanup_ok=False; cleanup_fail('REAP_FAILED', error)
                if admitted is not None:
                    try: verify(teardown)
                    except BaseException as error: cleanup_ok=False; cleanup_fail('BOUNDARY_FAILED', error)
                if complete:
                    try: need(frame(private) == result['frame'], 'FRAME_REFUSED')
                    except Refused as error: fail(error.reason)
                    except (KeyboardInterrupt, SystemExit): fail('CANCELLED')
                    except Exception: fail('FRAME_REFUSED')
                if origin == 'VERIFIED_SOFTWARE_RUNTIME':
                    for role in reserved:
                        try:
                            row=observe(role,teardown)
                        except Refused as error: fail(error.reason)
                        except (KeyboardInterrupt, SystemExit): fail('CANCELLED')
                        except Exception: fail('OUTPUT_BOUND')
                result['cleanup'] = 'PASS' if cleanup_ok else 'FAIL'
                if events: fail('CANCELLED')
                if time.monotonic() >= teardown:
                    cleanup_ok=False; result['cleanup']='FAIL'; cleanup_fail('DEADLINE'); fail('DEADLINE')
                if not cleanup_ok: fail('CLEANUP_FAILED')
    except (KeyboardInterrupt, SystemExit): fail('CANCELLED')
    except Exception:
        result['cleanup'] = 'FAIL'
        if result['cleanup_failure'] == 'NONE': result['cleanup_failure'] = 'BOUNDARY_FAILED'
        fail('BACKEND_ERROR')
    # Restoration can record/drain a signal after the body's last check.
    if events: fail('CANCELLED')
    try:
        elapsed = int((time.monotonic()-started)*1000)
        result.update(elapsed_ms=elapsed if 0 <= elapsed <= TOTAL*1000 else None)
        if complete and result['first_failure'] == 'NONE' and result['cleanup'] == 'PASS' and not result['cancelled']:
            result['status'] = 'PASS_CONTROLLED_FIXTURE' if origin == 'CONTROLLED_FIXTURE' else 'PASS_SOFTWARE'
            if origin == 'VERIFIED_SOFTWARE_RUNTIME': result['software_transport'] = 'PASS'
        elif result['first_failure'] == 'ADMISSION_UNAVAILABLE' and not result['cancelled']: result['status'] = 'BLOCKED'
        value = project(result)
        if events:
            fail('CANCELLED'); result.update(status='FAIL', software_transport='NOT RUN')
            value = project(result)
        return value
    except (KeyboardInterrupt, SystemExit):
        fail('CANCELLED'); result.update(status='FAIL', software_transport='NOT RUN')
        result.setdefault('elapsed_ms', None)
        return project(result)


def project(result):
    """Closed status projection; bytes/logs/IDs/argv and paths are never public."""
    keys={'schema_version','status','origin','first_failure','software_transport','physical_camera',
        'hardware','display_preview','performance','device_access','public_frame_export','cancelled','cleanup_failure','frame','cleanup',
        'graph_sha256','grant_pins','plan_sha256','actors','elapsed_ms'}
    need(type(result) is dict and set(result)==keys and type(result['schema_version']) is int and result['schema_version']==1)
    for key, allowed in [('status',{'FAIL','BLOCKED','PASS_CONTROLLED_FIXTURE','PASS_SOFTWARE'}),
        ('origin',{'UNAVAILABLE','CONTROLLED_FIXTURE','VERIFIED_SOFTWARE_RUNTIME'}),
        ('first_failure',REASONS|{'NONE'}),('cleanup',{'NOT_RUN','PASS','FAIL'}),
        ('cleanup_failure',{'NONE','OBSERVATION_FAILED','STOP_FAILED','REAP_FAILED','ABSENCE_UNVERIFIED','BOUNDARY_FAILED','DEADLINE'}),
        ('software_transport',{'NOT RUN','PASS'})]:
        need(type(result[key]) is str and result[key] in allowed)
    need(all(result[k]=='NOT RUN' for k in ('physical_camera','hardware','display_preview')) and result['performance']=='NOT MEASURED')
    need(result['device_access'] is False and result['public_frame_export'] is False)
    need(type(result['cancelled']) is bool and (result['elapsed_ms'] is None or
         type(result['elapsed_ms']) is int and 0<=result['elapsed_ms']<=60000))
    need(result['first_failure'] != 'CANCELLED' or result['cancelled'])
    need(not result['cancelled'] or result['status'] == 'FAIL')
    for key in ('plan_sha256','graph_sha256'):
        need(key=='graph_sha256' and result[key] is None or type(result[key]) is str and re.fullmatch('[0-9a-f]{64}',result[key]))
    pins=result['grant_pins']
    need(pins is None or type(pins) is dict and set(pins)==set(GRANTS) and
         all(type(v) is str and re.fullmatch('[0-9a-f]{64}',v) for v in pins.values()))
    need(type(result['actors']) is dict and set(result['actors'])==set(ROLES))
    for row in result['actors'].values():
        need(type(row) is dict and set(row)=={'launch','exit','exit_origin','natural_eos','reaped','cleanup_requests'})
        need(type(row['launch']) is str and row['launch'] in ('NOT_ATTEMPTED','UNKNOWN','PID_OBSERVED','NO_LAUNCH'))
        need(type(row['exit_origin']) is str and row['exit_origin'] in ('UNOBSERVED','PRE_STOP_RETURN','CLEANUP'))
        need(type(row['natural_eos']) is bool and type(row['reaped']) is bool)
        value=row['exit'];need(type(value) is dict and set(value)=={'kind','code'} and type(value['kind']) is str)
        need(value['code'] is None or type(value['code']) is int and -64<=value['code']<=255)
        need(value==exit_record(value['code']))
        need(type(row['cleanup_requests']) is list and row['cleanup_requests'] in ([],['TERM'],['KILL'],['TERM','KILL']))
    frame_row=result['frame']
    if frame_row is not None:
        need(type(frame_row) is dict and set(frame_row)=={'sha256','bytes','width','height','format'})
        need(type(frame_row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',frame_row['sha256']) and
             type(frame_row['bytes']) is int and 0<frame_row['bytes']<=FRAME_LIMIT and
             type(frame_row['width']) is int and frame_row['width']==160 and
             type(frame_row['height']) is int and frame_row['height']==120 and type(frame_row['format']) is str and frame_row['format']=='RGB8')
    if result['status'].startswith('PASS'):
        need(result['first_failure']==result['cleanup_failure']=='NONE' and result['cleanup']=='PASS' and not result['cancelled'] and
             frame_row is not None and result['elapsed_ms'] is not None and pins is not None and result['graph_sha256'] is not None)
        need(all(r['launch']=='PID_OBSERVED' and r['reaped'] and r['exit']['code'] is not None for r in result['actors'].values()))
        need(result['actors']['consumer']['natural_eos'] and result['actors']['consumer']['exit']==exit_record(0) and
             result['actors']['link']['exit']==exit_record(0))
        need((result['status']=='PASS_SOFTWARE')==(result['origin']=='VERIFIED_SOFTWARE_RUNTIME') and
             (result['status']=='PASS_SOFTWARE')==(result['software_transport']=='PASS'))
    else: need(result['software_transport']=='NOT RUN')
    if result['origin']=='CONTROLLED_FIXTURE':need(result['software_transport']=='NOT RUN')
    data=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(data)<=4096,'OUTPUT_BOUND')
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract',action='store_true',help='print inert backend requirements and command plan')
    args=parser.parse_args()
    value={'schema_version':1,'status':'BLOCKED','reason':'ADMISSION_UNAVAILABLE',
        'required_grants':list(GRANTS),'software_transport':'NOT RUN','physical_camera':'NOT RUN','hardware':'NOT RUN','device_access':False}
    if args.contract: value.update(command_plan=command_plan('0'*32), total_seconds=TOTAL,
        cleanup_seconds=CLEANUP, consumer_seconds=CONSUMER, actor_seconds=ACTOR,
        frame_limit=FRAME_LIMIT, log_limit=LOG_LIMIT)
    print(json.dumps(value,sort_keys=True,separators=(',',':')))
    return 2


if __name__ == '__main__': raise SystemExit(main())
