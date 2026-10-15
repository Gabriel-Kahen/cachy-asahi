#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit repository launch interposition. All Docker operations are injected.

Transport.run and .attach return {exit_code, stdout, stderr}; bytes are raw.
attach calls on_stdout(bytes), and obtains queued ACKs through on_stdin().
The transport must enforce the supplied absolute deadline and byte limit.
"""
from contextlib import contextmanager
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time

ORIGINAL_PIN = 'f860ff970093c7aac0788571d36ab32f1617e2dc9b2a703e42e16782f10a7641'
MARKER = b'\x1eRCNH1 '
ACK_MARKER = b'\x1eRCNH1-ACK '
RESERVED = b'\x1eRCNH1'
PHASES = ('pre-A-revocation', 'post-public-export')
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SYS_CHROOT')
SIGNALS = {signal.SIGINT, signal.SIGTERM}
LIMIT = 6 * 1024**2
_SCOPES = set()
_LOCK = threading.Lock()


class Refused(ValueError):
    pass


class Cancelled(KeyboardInterrupt):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    def invalid(_):
        raise Refused('noninteger JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def alive(deadline):
    cancellation_checkpoint()
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline,
         'launch deadline exceeded or invalid')


@contextmanager
def directory(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'parent traversal refused')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        before = os.fstat(fd)
        yield fd
        live = path.lstat()
        need((live.st_dev, live.st_ino, live.st_mode) == (before.st_dev, before.st_ino, before.st_mode),
             'directory identity drift')
    finally:
        os.close(fd)


def read(path, limit=1024**2):
    path = Path(path).absolute()
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
                 'bounded single-link file required')
            data = bytearray()
            while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
                data.extend(chunk)
                need(len(data) <= limit, 'file byte bound')
            after = os.fstat(fd); live = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(len(data) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(live, key)
                                                    for key in fields), 'file identity drift')
            return bytes(data)
        finally:
            os.close(fd)


def write_new(path, raw):
    path = Path(path).absolute()
    with directory(path.parent) as parent:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view); need(count > 0, 'short private write'); view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
        need(read(path, max(len(raw), 1)) == raw, 'private write reread differs')


def _raise_signal_faults(body_error, faults):
    """Keep the original object primary and retain every distinct secondary cause."""
    if not faults:
        return
    causes = []
    if body_error is not None and body_error.__cause__ is not None:
        causes.append(body_error.__cause__)
    for fault in faults:
        if fault is not body_error and not any(fault is item for item in causes):
            causes.append(fault)
    if not causes:
        return
    cause = causes[0] if len(causes) == 1 else BaseExceptionGroup('signal teardown failed', causes)
    if body_error is not None:
        raise body_error from cause
    raise cause


# SPDX-License-Identifier: MIT
# Original downstream adaptation of the reviewed common02398 signal transaction.
SIGNAL_SCOPES = []
CANCELLATION_EVENTS = set()
CANCELLATION_UNCERTAIN = set()
UNCERTAINTY = frozenset(('block','set','get','handler','pending','wait','mask','registry','replay'))

def cancellation_state(state=None):
    need(type(SIGNALS) is set and SIGNALS == {signal.SIGINT,signal.SIGTERM},'signal constants differ')
    need(type(UNCERTAINTY) is frozenset and UNCERTAINTY == frozenset(
         ('block','set','get','handler','pending','wait','mask','registry','replay')),'signal uncertainty constants differ')
    def number(value):
        return type(value) in (int,type(signal.SIGINT)) and value in SIGNALS
    def checked(value):
        need(type(value) is Cancellation and set(vars(value)) ==
             {'pending','depth','deferring','numbers','uncertain'}, 'signal state differs')
        need(type(value.pending) is bool and type(value.deferring) is bool and
             type(value.depth) is int and 0 <= value.depth <= 64 and
             type(value.numbers) is set and len(value.numbers) <= 2 and
             all(number(item) for item in value.numbers) and type(value.uncertain) is set and
             all(type(item) is str and item in UNCERTAINTY for item in value.uncertain),
             'signal state fields differ')
    need(type(SIGNAL_SCOPES) is list and len(SIGNAL_SCOPES) <= 64,'signal registry differs')
    for scope in SIGNAL_SCOPES:
        need(type(scope) is tuple and len(scope) == 5,'signal scope differs')
        owner,opaque,mask,deferred,depth = scope
        checked(owner)
        need(type(opaque) is tuple and len(opaque) <= 2 and all(number(item) for item in opaque) and
             len(set(opaque)) == len(opaque) and type(mask) is set and
             all(type(item) in (int,type(signal.SIGINT)) for item in mask) and
             type(deferred) is bool and type(depth) is int and 0 <= depth <= 64,'signal scope fields differ')
    for owner in [scope[0] for scope in SIGNAL_SCOPES]+([state] if state is not None else []):
        checked(owner)
        need(owner.depth == sum(scope[3] for scope in SIGNAL_SCOPES if scope[0] is owner),
             'signal deferral depth differs')
    need(type(CANCELLATION_EVENTS) is set and len(CANCELLATION_EVENTS) <= 3 and
         all(number(item) or type(item) is str and item == 'INTERRUPT' for item in CANCELLATION_EVENTS),
         'signal events differ')
    need(type(CANCELLATION_UNCERTAIN) is set and all(type(item) is str and item in UNCERTAINTY
         for item in CANCELLATION_UNCERTAIN),'signal uncertainty differs')

def cancellation_requested():
    cancellation_state(); return bool(CANCELLATION_EVENTS)

def cancellation_uncertain():
    cancellation_state(); return bool(CANCELLATION_UNCERTAIN)

def cancellation_checkpoint():
    cancellation_state()
    if SIGNAL_SCOPES:
        state,opaque,_,_,_ = SIGNAL_SCOPES[-1]
        pending = signal.sigpending()
        for number in opaque:
            if number in pending:
                signal.sigwait({number}); state.handler(number,None)

def retain_fault(primary, secondary):
    if primary is None: return secondary
    if secondary is primary: return primary
    try: _raise_signal_faults(primary,[secondary])
    except BaseException as first: return first

class Cancellation:
    def __init__(self):
        self.pending=False; self.depth=0; self.deferring=False
        self.numbers=set(); self.uncertain=set()

    @property
    def cancelled(self): return self.pending

    @cancelled.setter
    def cancelled(self,value): self.pending=value

    def handler(self, number, frame):
        cancellation_state(self)
        need(type(number) in (int,type(signal.SIGINT)) and number in SIGNALS,'signal number differs')
        self.pending=True; self.numbers.add(number); CANCELLATION_EVENTS.add(number)
        if not self.depth and not self.deferring: raise Cancelled('launch cancelled')

    @contextmanager
    def defer(self):
        with _signal_handlers(self,deferred=True): yield

@contextmanager
def _signal_handlers(state, *, deferred=False):
    global SIGNAL_SCOPES,CANCELLATION_EVENTS,CANCELLATION_UNCERTAIN
    need(threading.current_thread() is threading.main_thread(),'main-thread cancellation required')
    cancellation_state(state); need(type(deferred) is bool,'typed signal deferral required')
    registry,events,uncertain=SIGNAL_SCOPES,CANCELLATION_EVENTS,CANCELLATION_UNCERTAIN
    state_numbers,state_uncertain,depth=state.numbers,state.uncertain,state.depth
    prefix=tuple(registry); previous={}; scope=None; body_error=None
    mask=signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS)
    try:
        previous={number:signal.getsignal(number) for number in SIGNALS}
        inherited=registry[-1][1] if registry else ()
        opaque=tuple(number for number in SIGNALS if previous[number] is None and
                     (number not in mask or number in inherited))
        if deferred: state.depth += 1
        for number,original in previous.items():
            if original is not None: signal.signal(number,state.handler)
        scope=(state,opaque,set(mask),deferred,depth); registry.append(scope)
        signal.pthread_sigmask(signal.SIG_SETMASK,set(mask)|{
            number for number,original in previous.items() if original is None})
        # The exec target inherits the caller's mask, not enclosing polling blocks.
        yield set(registry[0][2])
    except BaseException as error:
        body_error=error; raise
    finally:
        faults,queued,unsafe=[],[],set()
        def failed(site,error):
            uncertain.add(site); state_uncertain.add(site)
            if isinstance(error,KeyboardInterrupt):
                events.add('INTERRUPT'); state.pending=True
            faults.append(error)
        try:
            blocked=False
            for _ in range(2):
                try:
                    signal.pthread_sigmask(signal.SIG_BLOCK,SIGNALS); blocked=True; break
                except BaseException as error: failed('block',error)
            if not blocked: unsafe.update(SIGNALS)
            for number,original in previous.items():
                if original is None: continue
                if not blocked:
                    unsafe.add(number); uncertain.add('handler'); state_uncertain.add('handler'); continue
                restored=False
                for _ in range(2):
                    try: signal.signal(number,original)
                    except BaseException as error: failed('set',error)
                    try: restored=signal.getsignal(number)==original
                    except BaseException as error: failed('get',error)
                    if restored: break
                if not restored:
                    unsafe.add(number); failed('get',Refused('signal handler restoration differs'))
            if blocked:
                for number in SIGNALS:
                    if number in mask and (scope is None or number not in scope[1]): continue
                    try: pending=number in signal.sigpending()
                    except BaseException as error:
                        unsafe.add(number); failed('pending',error); continue
                    if pending:
                        queued.append(number); consumed=False
                        for _ in range(2):
                            try: signal.sigwait({number}); consumed=True; break
                            except BaseException as error: failed('wait',error)
                        if not consumed: unsafe.add(number)
        finally:
            try:
                expected=prefix+((scope,) if scope is not None else ())
                if SIGNAL_SCOPES is not registry or len(registry)!=len(expected) or any(
                        actual is not wanted for actual,wanted in zip(registry,expected)):
                    failed('registry',Refused('signal scope restoration differs'))
                registry[:]=prefix; SIGNAL_SCOPES=registry; state.depth=depth
                for name,wanted in (('numbers',state_numbers),('uncertain',state_uncertain)):
                    if getattr(state,name) is not wanted:
                        failed('registry',Refused('signal state registry differs')); setattr(state,name,wanted)
                if CANCELLATION_EVENTS is not events:
                    failed('registry',Refused('signal event registry differs')); CANCELLATION_EVENTS=events
                if CANCELLATION_UNCERTAIN is not uncertain:
                    failed('registry',Refused('signal uncertainty registry differs')); CANCELLATION_UNCERTAIN=uncertain
            finally:
                target_mask=set(mask)|unsafe
                if unsafe: uncertain.add('mask'); state_uncertain.add('mask')
                for _ in range(2):
                    try: signal.pthread_sigmask(signal.SIG_SETMASK,target_mask); break
                    except BaseException as error: failed('mask',error)
        for number in queued:
            try: state.handler(number,None)
            except BaseException as error:
                if isinstance(error,KeyboardInterrupt): faults.append(error)
                else: failed('replay',error)
        # Relay opaque events through the shared Source scope, and known events
        # through the actual original callable. Never invoke an opaque disposition.
        for number in tuple(state_numbers):
            target=prefix[-1][0].handler if prefix else previous.get(number)
            if callable(target):
                try: target(number,None)
                except BaseException as error:
                    if isinstance(error,KeyboardInterrupt): faults.append(error)
                    else: failed('replay',error)
        if state.pending and not state.depth and not state.deferring:
            cancelled=Cancelled('launch cancelled after teardown')
            if body_error is None: _raise_signal_faults(cancelled,faults); raise cancelled
            if not isinstance(body_error,KeyboardInterrupt): faults.append(cancelled)
        _raise_signal_faults(body_error,faults)

@contextmanager
def cancellation_handlers(state):
    with _signal_handlers(state): yield


def validate_command(command, contract):
    """Validate the literal frozen command, including argument order and mounts."""
    need(isinstance(command, (list, tuple)) and all(isinstance(x, str) for x in command), 'typed command required')
    need(isinstance(contract, dict) and contract.get('script_sha256') == ORIGINAL_PIN
         and contract.get('schema_version') == 1 and type(contract['schema_version']) is int
         and contract.get('purpose') == 'disposable-generic-repository-test'
         and contract.get('execution') == 'native-aarch64-disposable-docker'
         and contract.get('allow_system_mutation') is True and contract.get('daemon_arch') == 'aarch64'
         and contract.get('upgrade_kind') == 'synthetic-changed-package-fixtures', 'frozen contract required')
    nonce, image = contract.get('nonce'), contract.get('image_id')
    need(isinstance(contract.get('source_commit'), str) and re.fullmatch('[0-9a-f]{40}', contract['source_commit']),
         'workflow source commit required')
    need(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce)
         and isinstance(image, str) and re.fullmatch('sha256:[0-9a-f]{64}', image), 'nonce/image required')
    name = 'cachy-asahi-repository-' + nonce
    prefix = ['docker', 'run', '--name', name, '--pull=never', '--platform=linux/arm64', '--user', '0:0',
              '--network=none', '--cgroupns=private', '--cap-drop=ALL', '--security-opt=no-new-privileges',
              '--pids-limit=512', '--memory=8g', '--cpus=4']
    prefix += ['--cap-add=' + cap for cap in CAPS]
    prefix += ['--read-only', '--tmpfs', '/scratch:rw,nosuid,nodev,exec,size=6g,mode=0700',
               '--tmpfs', '/test-home:rw,nosuid,nodev,exec,size=128m,mode=0700']
    need(list(command[:len(prefix)]) == prefix, 'original runtime policy differs')
    position = len(prefix); binds = {}
    for dest, readonly in (('/inputs', True), ('/runner', True), ('/out', False)):
        need(command[position] == '--mount', 'original mounts differ')
        value = command[position + 1]; suffix = ',dst=' + dest + (',readonly' if readonly else '')
        need(value.startswith('type=bind,src=') and value.endswith(suffix), 'original mount differs')
        source = value[len('type=bind,src='):-len(suffix)]
        need(source.startswith('/') and not re.search('[,\n\r]', source) and '..' not in Path(source).parts,
             'canonical mount required')
        binds[dest] = Path(source); position += 2
    expected = ['--env', 'CACHY_ASAHI_REPOSITORY_CONTAINER=1', '--env', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=' + nonce,
                '--env', 'CACHY_ASAHI_IMAGE_ID=' + image, '--entrypoint=/usr/bin/python3', image,
                '-B', '/runner/repository.py', '--inputs', '/inputs/manifest.json', '--inputs-sha256']
    need(list(command[position:-2]) == expected and command[-1] == '--allow-disposable-repository-test',
         'original producer command differs')
    manifest = read(binds['/inputs'] / 'manifest.json')
    need(digest(manifest) == command[-2] and decode(manifest) == contract, 'actual pinned manifest differs')
    need(digest(read(binds['/runner'] / 'repository.py')) == ORIGINAL_PIN, 'frozen runner bytes differ')
    paths = list(binds.values())
    need(all(a != b and a not in b.parents and b not in a.parents for i, a in enumerate(paths) for b in paths[i+1:]),
         'mount overlap refused')
    for path in paths:
        with directory(path):
            pass
    need(not any(binds['/out'].iterdir()), 'original output must start empty')
    return {'name': name, 'image': image, 'nonce': nonce, 'binds': binds}


class Protocol:
    def __init__(self, nonce, handler, deadline):
        self.nonce, self.handler, self.deadline = nonce, handler, deadline
        self.buffer = bytearray(); self.plain = bytearray(); self.acks = []
        self.frames = []; self.previous = '0' * 64; self.wire_bytes = 0
        self.raw = bytearray()

    def feed(self, chunk):
        alive(self.deadline)
        need(isinstance(chunk, bytes), 'typed attach stdout required')
        self.wire_bytes += len(chunk); need(self.wire_bytes <= 2 * LIMIT + 4 * 1024**2, 'attach output bound')
        self.raw.extend(chunk)
        self.buffer.extend(chunk)
        need(len(self.buffer) <= LIMIT, 'checkpoint wire bound')
        while b'\n' in self.buffer:
            line, _, rest = self.buffer.partition(b'\n'); self.buffer = bytearray(rest)
            if RESERVED in line:
                need(line.startswith(MARKER) and len(self.frames) < 2, 'reserved malformed/extra checkpoint')
                raw = bytes(line[len(MARKER):]); frame = decode(raw)
                need(isinstance(frame, dict) and set(frame) == {'schema_version', 'purpose', 'nonce', 'sequence', 'phase', 'payload',
                     'payload_sha256', 'previous_frame_sha256'} and encoded(frame) == raw, 'canonical checkpoint required')
                sequence = len(self.frames) + 1
                need(type(frame['schema_version']) is int and frame['schema_version'] == 1
                     and frame['purpose'] == 'repository-native-checkpoint' and frame['nonce'] == self.nonce
                     and type(frame['sequence']) is int and frame['sequence'] == sequence
                     and frame['phase'] == PHASES[sequence - 1] and frame['previous_frame_sha256'] == self.previous,
                     'checkpoint identity/order differs')
                payload = base64.b64decode(frame['payload'], validate=True)
                need(len(payload) <= 4 * 1024**2 and digest(payload) == frame['payload_sha256'], 'checkpoint payload differs')
                frame_pin = digest(raw); end = min(self.deadline, time.monotonic() + 30)
                ack = self.handler(frame, end); alive(end)
                expected = {'schema_version': 1, 'purpose': 'repository-native-checkpoint-ack',
                            'nonce': self.nonce, 'sequence': sequence, 'phase': frame['phase'],
                            'frame_sha256': frame_pin, 'durable_host_digest': True}
                need(ack == ACK_MARKER + encoded(expected) + b'\n', 'durable checkpoint ACK differs')
                self.acks.append(ack); self.frames.append({'sequence': sequence, 'phase': frame['phase'],
                    'frame_sha256': frame_pin, 'payload_sha256': frame['payload_sha256']})
                self.previous = frame_pin
            else:
                self.plain.extend(line + b'\n'); need(len(self.plain) <= 4 * 1024**2, 'plain launcher log bound')

    def stdin(self):
        return self.acks.pop(0) if self.acks else None

    def finish(self):
        need(not self.buffer or RESERVED not in self.buffer and not any(self.buffer.endswith(RESERVED[:n])
             for n in range(1, len(RESERVED) + 1)), 'partial checkpoint refused')
        self.plain.extend(self.buffer); self.buffer.clear()
        need(len(self.frames) == 2 and not self.acks and len(self.plain) <= 4 * 1024**2, 'two delivered ACKs required')


def _cap_add_matches(value, _caps=CAPS):
    """Accept only six distinct frozen capabilities, bare or Docker CAP_ names."""
    if type(value) is not list or len(value) != 6:
        return False
    seen = set()
    for item in value:
        if type(item) is not str or len(item) > 32:
            return False
        name = item[4:] if item.startswith('CAP_') else item
        if name not in _caps or name in seen:
            return False
        seen.add(name)
    return len(seen) == len(_caps)


def inspect_owned(value, expected, *, terminal=False):
    try:
        need(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), 'one inspect record required')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_SHAPE')
        raise
    row = value[0]; config, host = row.get('Config', {}), row.get('HostConfig', {})
    try:
        need(row.get('Id') == expected['cid'] and row.get('Name') == '/' + expected['name']
             and row.get('Image') == expected['image'], 'container ownership differs')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_IDENTITY')
        raise
    required_env = {'CACHY_ASAHI_REPOSITORY_CONTAINER=1', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=' + expected['nonce'],
                    'CACHY_ASAHI_IMAGE_ID=' + expected['image']}
    try:
        need(config.get('User') == '0:0' and config.get('OpenStdin') is True and config.get('Tty') is False
             and config.get('Entrypoint') == ['/usr/bin/python3'] and config.get('Cmd') == expected['worker_args']
             and isinstance(config.get('Env'), list) and required_env <= set(config['Env'])
             and all(sum(item.startswith(key) for item in config['Env']) == 1 for key in
                     ('CACHY_ASAHI_REPOSITORY_CONTAINER=', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=', 'CACHY_ASAHI_IMAGE_ID=')),
             'created producer config differs')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_CONFIG')
        raise
    try:
        need(host.get('NetworkMode') == 'none' and host.get('CgroupnsMode') == 'private'
             and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
             and host.get('CapDrop') == ['ALL'] and type(host.get('CapAdd')) is list
             and len(host['CapAdd']) == 6 and _cap_add_matches(host['CapAdd'])
             and host.get('PidsLimit') == 512 and host.get('Memory') == 8 * 1024**3
             and host.get('NanoCpus') == 4 * 10**9 and host.get('SecurityOpt') == ['no-new-privileges']
             and host.get('Tmpfs') == {'/scratch': 'rw,nosuid,nodev,exec,size=6g,mode=0700',
                                      '/test-home': 'rw,nosuid,nodev,exec,size=128m,mode=0700'}
             and not any(host.get(key) for key in ('Devices', 'DeviceRequests', 'Binds', 'VolumesFrom')),
             'created resource policy differs')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_RESOURCES')
        _capture_resource_snapshot(_diagnostic_error, host)
        raise
    mounts = row.get('Mounts')
    try:
        need(isinstance(mounts, list) and all(isinstance(m, dict) for m in mounts)
             and len({m.get('Destination') for m in mounts}) == len(mounts), 'created mounts malformed')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_MOUNT_SHAPE')
        raise
    binds = [m for m in mounts if m.get('Type') == 'bind']
    try:
        need(len(binds) == 3 and {m.get('Destination') for m in binds} == set(expected['binds'])
             and all(m.get('Source') == str(expected['binds'][m['Destination']])
                     and m.get('RW') is (m['Destination'] == '/out') for m in binds)
             and all(m.get('Type') == 'bind' or m.get('Type') == 'tmpfs'
                     and m.get('Destination') in ('/scratch', '/test-home') and m.get('RW') is True
                     and m.get('Source') in ('', None) for m in mounts), 'created bind mounts differ')
    except BaseException as _diagnostic_error:
        _label_inspect(_diagnostic_error, 'INSPECT_MOUNTS')
        raise
    if terminal:
        state = row.get('State', {})
        try:
            need(state.get('Status') == 'exited' and state.get('Running') is False and state.get('OOMKilled') is False
                 and type(state.get('ExitCode')) is int and state['ExitCode'] == 0 and state.get('Error') == '',
                 'producer terminal state differs')
        except BaseException as _diagnostic_error:
            _label_inspect(_diagnostic_error, 'INSPECT_TERMINAL')
            raise
    return row



INSPECT_DIAGNOSTIC_CHECKS = frozenset(('INSPECT_SHAPE', 'INSPECT_IDENTITY', 'INSPECT_CONFIG',
    'INSPECT_RESOURCES', 'INSPECT_MOUNT_SHAPE', 'INSPECT_MOUNTS', 'INSPECT_TERMINAL'))
LAUNCH_DIAGNOSTIC_OPERATIONS = frozenset(('NONE', 'OTHER', 'CONTRACT', 'PRIVATE_CUSTODY',
    'PREPARE_OBSERVER', 'OBSERVER_SOURCE', 'IMAGE_INSPECT', 'DAEMON_ARCH', 'NAME_AVAILABILITY',
    'CREATE', 'INSPECT_CREATED', 'ATTACH', 'CHECKPOINT_FINISH', 'INSPECT_TERMINAL',
    'PRODUCER_PASS', 'SOURCE_RECHECK', 'CANCELLATION_BOUNDARY', 'CLEANUP', 'PUBLICATION',
    'OWNERSHIP_RECOVERY', 'OWNERSHIP_INSPECT', 'REMOVE', 'ABSENCE_QUERY', 'ABSENCE_VERIFY',
    'PRIVATE_RECEIPT_OPEN', 'PLAIN_LOG', 'CLEANUP_LOG', 'LAUNCHER_LOG', 'RECEIPT_COMMIT'))


def _label_inspect(error, label, _refused=Refused, _checks=INSPECT_DIAGNOSTIC_CHECKS):
    try:
        if type(error) is _refused and type(label) is str and label in _checks:
            BaseException.__setattr__(error, '_repository_inspect_check', label)
    except BaseException:
        pass


def _inspect_diagnostic(error, _refused=Refused,
                        _need_code=need.__code__, _caller_code=inspect_owned.__code__,
                        _checks=INSPECT_DIAGNOSTIC_CHECKS):
    try:
        if type(error) is not _refused:
            return 'OTHER'
        label = BaseException.__getattribute__(error, '_repository_inspect_check')
        if type(label) is not str or label not in _checks:
            return 'OTHER'
        trace = BaseException.__getattribute__(error, '__traceback__')
        tail = []; count = 0
        while trace is not None:
            count += 1
            if count > 32:
                return 'OTHER'
            tail.append(trace.tb_frame)
            if len(tail) > 2:
                tail.pop(0)
            trace = trace.tb_next
        if len(tail) == 2 and tail[0].f_code is _caller_code and tail[1].f_code is _need_code                 and all(frame.f_globals is globals() for frame in tail):
            return label
    except BaseException:
        pass
    return 'OTHER'


# Source fragment for a proposed optional diagnostic; no admission logic.
RESOURCE_FIELDS = ('known_mask', 'failed_mask', 'network_none', 'cgroup_private',
    'readonly_rootfs', 'privileged', 'pids_limit', 'memory', 'nano_cpus',
    'cap_add_is_list', 'cap_add_count', 'cap_add_plain_mask', 'cap_add_prefixed_mask', 'cap_add_unknown_count',
    'cap_add_effective_duplicates', 'cap_drop_count', 'cap_drop_all',
    'security_opt_count', 'security_bare_nnp', 'security_true_nnp', 'security_false_nnp',
    'tmpfs_count', 'scratch_tmpfs_match', 'home_tmpfs_match',
    'extras_known_mask', 'extras_presence_mask')


def _resource_snapshot(host, _caps=CAPS, _fields=RESOURCE_FIELDS):
    """Fixed typed observations only; never return HostConfig or its strings."""
    if type(host) is not dict or len(host) > 256 or any(type(key) is not str or len(key) > 128 for key in host):
        return None
    result = dict.fromkeys(_fields, None)
    clauses = []
    def observe(condition, ready=True):
        clauses.append(bool(condition) if ready else None)
    def string_match(key, expected):
        value = host.get(key)
        return value == expected if type(value) is str else None
    def integer(key):
        value = host.get(key)
        return value if type(value) is int and -1 <= value <= 2**63-1 else None
    def strings(key):
        value = host.get(key)
        return value if type(value) is list and len(value) <= 64 and all(
            type(item) is str and len(item) <= 128 for item in value) else None
    for key, field, expected in (('NetworkMode','network_none','none'),
                                  ('CgroupnsMode','cgroup_private','private')):
        result[field] = string_match(key, expected)
        observe(result[field], result[field] is not None)
    for key, field, expected in (('ReadonlyRootfs','readonly_rootfs',True),
                                  ('Privileged','privileged',False)):
        value = host.get(key)
        result[field] = value if type(value) is bool else None
        observe(value is expected, result[field] is not None)
    drop = strings('CapDrop'); result['cap_drop_count'] = len(drop) if drop is not None else None
    result['cap_drop_all'] = drop == ['ALL'] if drop is not None else None
    observe(result['cap_drop_all'], drop is not None)
    add = strings('CapAdd'); raw_add = host.get('CapAdd')
    result['cap_add_is_list'] = type(raw_add) is list if type(raw_add) in (list,dict,str,int,bool,float,type(None)) else None
    observe(result['cap_add_is_list'], result['cap_add_is_list'] is not None)
    result['cap_add_count'] = len(raw_add) if type(raw_add) is list and len(raw_add) <= 64 else None
    observe(result['cap_add_count'] == 6, result['cap_add_count'] is not None)
    observe(_cap_add_matches(add, _caps) if add is not None else False, add is not None)
    if add is not None:
        plain = prefixed = unknown = duplicates = seen = 0
        for item in add:
            bit = 0
            for number, cap in enumerate(_caps):
                if item == cap: bit = 1 << number; plain |= bit
                elif item == 'CAP_' + cap: bit = 1 << number; prefixed |= bit
            if not bit: unknown += 1
            elif seen & bit: duplicates += 1
            seen |= bit
        result.update(cap_add_plain_mask=plain, cap_add_prefixed_mask=prefixed,
                      cap_add_unknown_count=unknown, cap_add_effective_duplicates=duplicates)
    for key, field, expected in (('PidsLimit','pids_limit',512), ('Memory','memory',8*1024**3),
                                  ('NanoCpus','nano_cpus',4*10**9)):
        result[field] = integer(key); observe(result[field] == expected, result[field] is not None)
    security = strings('SecurityOpt')
    result['security_opt_count'] = len(security) if security is not None else None
    for field, token in (('security_bare_nnp','no-new-privileges'),
                         ('security_true_nnp','no-new-privileges:true'),
                         ('security_false_nnp','no-new-privileges:false')):
        result[field] = token in security if security is not None else None
    observe(security == ['no-new-privileges'], security is not None)
    tmpfs = host.get('Tmpfs'); typed = type(tmpfs) is dict and len(tmpfs) <= 64 and all(
        type(key) is str and len(key) <= 128 and type(value) is str and len(value) <= 256 for key,value in tmpfs.items())
    result['tmpfs_count'] = len(tmpfs) if typed else None
    for field, key, expected in (('scratch_tmpfs_match','/scratch','rw,nosuid,nodev,exec,size=6g,mode=0700'),
                                 ('home_tmpfs_match','/test-home','rw,nosuid,nodev,exec,size=128m,mode=0700')):
        result[field] = tmpfs.get(key) == expected if typed else None
    observe(result['tmpfs_count'] == 2 and result['scratch_tmpfs_match'] and result['home_tmpfs_match'], typed)
    known = present = 0
    for number,key in enumerate(('Devices','DeviceRequests','Binds','VolumesFrom')):
        value = host.get(key)
        if type(value) in (list,dict,str,int,bool,float,type(None)):
            known |= 1 << number
            if value: present |= 1 << number
    result.update(extras_known_mask=known, extras_presence_mask=present)
    observe(present == 0, known == 15)
    result['known_mask'] = sum(1 << number for number,value in enumerate(clauses) if value is not None)
    result['failed_mask'] = sum(1 << number for number,value in enumerate(clauses) if value is False)
    return result


def _closed_resource_snapshot(value, _fields=RESOURCE_FIELDS):
    """A malformed optional observation becomes unknown, never a new cause."""
    try:
        if type(value) is not dict or len(value) != len(_fields) or any(type(key) is not str for key in value): return None
        if set(value) != set(_fields): return None
        result = {}
        for field in _fields:
            item = value[field]
            if field in ('network_none','cgroup_private','readonly_rootfs','privileged','cap_drop_all',
                         'security_bare_nnp','security_true_nnp','security_false_nnp',
                         'scratch_tmpfs_match','home_tmpfs_match','cap_add_is_list'):
                if item is not None and type(item) is not bool: return None
            else:
                limit = (2**63-1 if field in ('pids_limit','memory','nano_cpus') else
                         16383 if field in ('known_mask','failed_mask') else
                         15 if field in ('extras_known_mask','extras_presence_mask') else
                         63 if field in ('cap_add_plain_mask','cap_add_prefixed_mask') else 64)
                minimum = -1 if field in ('pids_limit','memory','nano_cpus') else 0
                if item is not None and (type(item) is not int or not minimum <= item <= limit): return None
            result[field] = item
        if type(result['known_mask']) is not int or type(result['failed_mask']) is not int: return None
        if result['failed_mask'] & ~result['known_mask']: return None
        if type(result['extras_known_mask']) is not int or type(result['extras_presence_mask']) is not int: return None
        if result['extras_presence_mask'] & ~result['extras_known_mask']: return None
        cap_fields = ('cap_add_count','cap_add_plain_mask','cap_add_prefixed_mask',
                      'cap_add_unknown_count','cap_add_effective_duplicates')
        if all(type(result[field]) is int for field in cap_fields):
            effective = result['cap_add_plain_mask'] | result['cap_add_prefixed_mask']
            if effective.bit_count() + result['cap_add_unknown_count'] + result['cap_add_effective_duplicates'] != result['cap_add_count']: return None
            if (result['cap_add_plain_mask'] & result['cap_add_prefixed_mask']).bit_count() > result['cap_add_effective_duplicates']: return None
        return result
    except BaseException:
        return None


def _capture_resource_snapshot(error, host, _refused=Refused):
    try:
        if type(error) is _refused and _inspect_diagnostic(error) == 'INSPECT_RESOURCES':
            value = _closed_resource_snapshot(_resource_snapshot(host))
            if value is not None: BaseException.__setattr__(error, '_repository_resource_snapshot', value)
    except BaseException:
        pass


def _resource_diagnostic(error, _refused=Refused):
    try:
        if type(error) is _refused and _inspect_diagnostic(error) == 'INSPECT_RESOURCES':
            return _closed_resource_snapshot(BaseException.__getattribute__(error, '_repository_resource_snapshot'))
    except BaseException:
        pass
    return None


def _observe_launch_diagnostic(observation, channel, operation, error,
                              _operations=LAUNCH_DIAGNOSTIC_OPERATIONS):
    try:
        if channel not in ('first', 'cleanup', 'publication'):
            return
        if observation[channel + '_operation'] == 'NONE':
            observation[channel + '_operation'] = (operation if type(operation) is str
                and operation in _operations else 'OTHER')
            observation[channel + '_check'] = _inspect_diagnostic(error)
            observation[channel + '_resources'] = _resource_diagnostic(error)
    except BaseException:
        pass


def _public_launch_diagnostic(observation, _operations=LAUNCH_DIAGNOSTIC_OPERATIONS,
                             _checks=INSPECT_DIAGNOSTIC_CHECKS):
    result = {'schema_version': 1}
    for channel in ('first', 'cleanup', 'publication'):
        operation = check = 'OTHER'
        try:
            candidate = observation[channel + '_operation']
            if type(candidate) is str and candidate in _operations:
                operation = candidate
            candidate = observation[channel + '_check']
            if type(candidate) is str and candidate in _checks | {'NONE', 'OTHER'}:
                check = candidate
        except BaseException:
            pass
        result[channel + '_operation'] = operation
        result[channel + '_check'] = check if operation == 'NONE' or check != 'NONE' else 'OTHER'
        resources = None
        try:
            if type(observation) is dict and len(observation) <= 64 and all(type(key) is str for key in observation):
                if check == 'INSPECT_RESOURCES': resources = _closed_resource_snapshot(observation.get(channel + '_resources'))
        except BaseException:pass
        result[channel + '_resources'] = resources
    return result


def run_repository(command, log, private_root, original_executor, *, contract, run, deadline,
                   checkpoint_handler, producer_pin, prepare_runner=None):
    """Return observed custody receipt, or raise Refused carrying failed receipt."""
    names = [command[i+1] for i, item in enumerate(command[:-1]) if item == '--name']
    if not any(name.startswith('cachy-asahi-repository-') for name in names):
        return original_executor(command, log)
    receipt = {'status': 'FAIL', 'container_id': None, 'ownership_verified': False, 'cleanup': 'FAIL',
               'name_absence_verified': False, 'id_absence_verified': False, 'absence_verified': False,
               'checkpoints': [], 'commands': [], 'native_admission': 'NOT RUN'}
    state = Cancellation(); submitted = False; expected = None; work = None; protocol = None; fault = None
    diagnostic = {channel + '_' + field: 'NONE' for channel in ('first', 'cleanup', 'publication')
                  for field in ('operation', 'check')}
    diagnostic.update({channel + '_resources': None for channel in ('first','cleanup','publication')})
    operation = cleanup_operation = publication_operation = 'OTHER'
    receipt['diagnostic'] = diagnostic
    def call(argv, end):
        alive(end); value = run.run(list(map(str, argv)), deadline=end, limit=LIMIT)
        record(argv, value); alive(end)
        need(value['exit_code'] == 0, 'Docker operation failed'); return value['stdout']
    def record(argv, value, byte_limit=LIMIT):
        need(isinstance(value, dict) and set(value) == {'exit_code', 'stdout', 'stderr'}
             and type(value['exit_code']) is int and isinstance(value['stdout'], bytes) and isinstance(value['stderr'], bytes)
             and len(value['stdout']) + len(value['stderr']) <= byte_limit, 'bounded typed transport response required')
        number = len(receipt['commands']); need(number < 32, 'finite Docker operation count required')
        total = sum(row[key]['bytes'] for row in receipt['commands'] for key in ('stdout', 'stderr'))
        need(total + len(value['stdout']) + len(value['stderr']) <= 64 * 1024**2, 'private command aggregate bound')
        paths = []
        for key in ('stdout', 'stderr'):
            path = work / f'{number:02d}.{key}'; write_new(path, value[key]); paths.append(path.name)
        receipt['commands'].append({'argv': list(map(str, argv)), 'exit_code': value['exit_code'],
            **{key: {'path': paths[i], 'sha256': digest(value[key]), 'bytes': len(value[key])}
               for i, key in enumerate(('stdout', 'stderr'))}})
    try:
        with cancellation_handlers(state):
            try:
                operation = 'CONTRACT'
                alive(deadline); value = contract(command) if callable(contract) else contract
                expected = validate_command(command, value); receipt.update(container=expected['name'], image_id=expected['image'], nonce=expected['nonce'])
                operation = 'PRIVATE_CUSTODY'
                root = Path(private_root).absolute()
                with directory(root) as fd:
                    need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'private custody mode required')
                need(all(root != path and root not in path.parents and path not in root.parents for path in expected['binds'].values()),
                     'custody/mount overlap refused')
                work = root / ('launch-' + expected['nonce']); work.mkdir(mode=0o700)
                if prepare_runner is not None:
                    operation = 'PREPARE_OBSERVER'
                    prepared = prepare_runner(command)
                    need(prepared is None or prepared == producer_pin, 'prepared observer pin differs')
                operation = 'OBSERVER_SOURCE'
                alive(deadline); validate_command(command, value)
                need(isinstance(producer_pin, str) and re.fullmatch('[0-9a-f]{64}', producer_pin)
                     and digest(read(expected['binds']['/runner'] / 'producer.py')) == producer_pin, 'observer source differs')
                cidfile = work / 'cid'
                operation = 'IMAGE_INSPECT'
                image = decode(call(['docker', 'image', 'inspect', expected['image']], deadline))
                need(isinstance(image, list) and len(image) == 1 and image[0].get('Id') == expected['image']
                     and image[0].get('Architecture') == 'arm64' and image[0].get('Os') == 'linux', 'native image differs')
                operation = 'DAEMON_ARCH'
                daemon = call(['docker', 'info', '--format', '{{.Architecture}}'], deadline)
                need(daemon.strip() in (b'arm64', b'aarch64'), 'native daemon required')
                operation = 'NAME_AVAILABILITY'
                listing = call(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                                'name=^/' + expected['name'] + '$', '--format', '{{.ID}} {{.Names}}'], deadline)
                need(listing == b'', 'repository name already occupied')
                operation = 'CREATE'
                original = list(command); create = ['docker', 'create', '-i', '--cidfile', str(cidfile)] + original[2:]
                index = create.index('/runner/repository.py')
                create[index:index+1] = ['-I', '/runner/producer.py', '--handoff-deadline', repr(deadline)]
                expected['worker_args'] = create[create.index(expected['image'])+1:]
                receipt.update(original_command=original, actual_create_command=create, producer_sha256=producer_pin)
                with state.defer():
                    submitted = True
                    raw = call(create, deadline)
                    cid = read(cidfile, 128).decode().strip()
                    need(re.fullmatch('[0-9a-f]{64}', cid) and raw.strip().decode() == cid, 'full creation CID differs')
                    expected['cid'] = cid; receipt['container_id'] = cid
                operation = 'INSPECT_CREATED'
                inspect_owned(decode(call(['docker', 'container', 'inspect', cid], deadline)), expected)
                receipt['ownership_verified'] = True
                operation = 'ATTACH'
                protocol = Protocol(expected['nonce'], checkpoint_handler, deadline)
                argv = ['docker', 'start', '--attach', '--interactive', cid]
                response = run.attach(argv, on_stdout=protocol.feed, on_stdin=protocol.stdin, deadline=deadline, limit=2*LIMIT+4*1024**2)
                record(argv, response, 2*LIMIT+4*1024**2); alive(deadline)
                need(response['exit_code'] == 0 and RESERVED not in response['stderr']
                     and response['stdout'] == bytes(protocol.raw), 'attach failed or raw callback stream differs')
                operation = 'CHECKPOINT_FINISH'
                protocol.finish(); receipt['checkpoints'] = protocol.frames
                operation = 'INSPECT_TERMINAL'
                inspect_owned(decode(call(['docker', 'container', 'inspect', cid], deadline)), expected, terminal=True)
                operation = 'PRODUCER_PASS'
                need(b'PASS: disposable generic repository transactions; hardware/stable gates unchanged.' in protocol.plain,
                     'original producer PASS missing')
                operation = 'SOURCE_RECHECK'
                need(digest(read(expected['binds']['/runner'] / 'repository.py')) == ORIGINAL_PIN
                     and digest(read(expected['binds']['/runner'] / 'producer.py')) == producer_pin
                     and digest(read(expected['binds']['/inputs'] / 'manifest.json')) == command[-2],
                     'source or contract drift after producer')
                receipt['status'] = 'PASS'
            except BaseException as error:
                _observe_launch_diagnostic(diagnostic, 'first', operation, error)
                fault = error; receipt['error_type'] = type(fault).__name__
            finally:
                if submitted:
                    try:
                        with state.defer():
                            cleanup_end = time.monotonic() + 30
                            if 'cid' not in expected:
                                receipt['ownership_uncertain'] = True; receipt['status'] = 'FAIL'
                                cleanup_operation = 'OWNERSHIP_RECOVERY'
                                rows = decode(call(['docker', 'container', 'inspect', expected['name']], cleanup_end))
                                need(isinstance(rows, list) and len(rows) == 1 and re.fullmatch('[0-9a-f]{64}', rows[0].get('Id', '')),
                                     'partial creation recovery uncertain')
                                # A name lookup is an observation, not creation ownership.
                                # Only the private Docker-written full CID permits disposal.
                                recovered = read(cidfile, 128).decode().strip()
                                need(re.fullmatch('[0-9a-f]{64}', recovered) and rows[0]['Id'] == recovered,
                                     'recovery lacks matching private creation CID')
                                expected['cid'] = recovered; receipt['container_id'] = expected['cid']
                                inspect_owned(rows, expected)
                            else:
                                cleanup_operation = 'OWNERSHIP_INSPECT'
                                inspect_owned(decode(call(['docker', 'container', 'inspect', expected['cid']], cleanup_end)), expected)
                            cleanup_operation = 'REMOVE'
                            call(['docker', 'container', 'rm', '-f', expected['cid']], cleanup_end)
                            cleanup_operation = 'ABSENCE_QUERY'
                            listing = call(['docker', 'container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}'], cleanup_end)
                            rows = [line.split() for line in listing.decode().splitlines()]
                            need(all(len(row) == 2 and re.fullmatch('[0-9a-f]{64}', row[0]) for row in rows), 'absence query malformed')
                            receipt['name_absence_verified'] = all(expected['name'] not in row[1].split(',') for row in rows)
                            receipt['id_absence_verified'] = all(expected['cid'] != row[0] for row in rows)
                            receipt['absence_verified'] = receipt['name_absence_verified'] and receipt['id_absence_verified']
                            cleanup_operation = 'ABSENCE_VERIFY'
                            need(receipt['absence_verified'], 'name or ID remains')
                            receipt['cleanup'] = 'PASS'
                    except BaseException as error:
                        _observe_launch_diagnostic(diagnostic, 'cleanup', cleanup_operation, error)
                        _observe_launch_diagnostic(diagnostic, 'first', 'CLEANUP', error)
                        fault = retain_fault(fault,error); receipt['status'] = 'FAIL'; receipt['cleanup_error_type'] = type(error).__name__
    except BaseException as error:
        _observe_launch_diagnostic(diagnostic, 'first', 'CANCELLATION_BOUNDARY', error)
        fault = retain_fault(fault,error); receipt['status'] = 'FAIL'; receipt['error_type'] = type(fault).__name__
    if state.uncertain:
        receipt.update(status='FAIL',cleanup='FAIL',signal_teardown_uncertain=True)
    if state.pending:
        receipt.update(status='FAIL', cancelled=True)
    if work is not None:
        summary = {key: receipt[key] for key in ('status', 'container_id', 'ownership_verified', 'cleanup',
                   'name_absence_verified', 'id_absence_verified', 'absence_verified', 'native_admission')}
        summary['container'] = receipt.get('container'); summary['cancelled'] = state.pending
        receipt['private_root'] = str(work)
        # Protocol bytes never enter the original public launcher stream.
        receipt_fd = None
        def commit():
            raw = encoded(receipt) + b'\n'
            os.ftruncate(receipt_fd, 0); os.lseek(receipt_fd, 0, os.SEEK_SET)
            view = memoryview(raw)
            while view:
                count = os.write(receipt_fd, view); need(count > 0, 'receipt write failed'); view = view[count:]
            os.fsync(receipt_fd)
        try:
            with cancellation_handlers(state):
                with state.defer():
                    publication_operation = 'PRIVATE_RECEIPT_OPEN'
                    with directory(work) as parent:
                        receipt_fd = os.open('receipt.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o600, dir_fd=parent)
                        os.fsync(parent)
                    publication_operation = 'PLAIN_LOG'
                    write_new(log, bytes(protocol.plain) if protocol is not None else b'')
                    publication_operation = 'CLEANUP_LOG'
                    write_new(Path(log).with_suffix('.cleanup.json'), encoded(dict(summary, status=receipt['cleanup'])) + b'\n')
                    publication_operation = 'LAUNCHER_LOG'
                    write_new(Path(log).with_suffix('.launcher.json'), encoded({'status': receipt['status'], 'diagnostic': _public_launch_diagnostic(diagnostic)}) + b'\n')
                    if state.pending:
                        receipt.update(status='FAIL', cancelled=True)
                    publication_operation = 'RECEIPT_COMMIT'
                    commit()
                    if state.pending:
                        receipt.update(status='FAIL', cancelled=True); commit()
        except BaseException as error:
            _observe_launch_diagnostic(diagnostic, 'publication', publication_operation, error)
            _observe_launch_diagnostic(diagnostic, 'first', 'PUBLICATION', error)
            fault = retain_fault(fault,error); receipt['status'] = 'FAIL'; receipt['publication_error_type'] = type(error).__name__
            receipt['cancelled'] = state.pending or isinstance(error, (Cancelled, KeyboardInterrupt))
            if receipt_fd is not None:
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
                try:
                    commit()
                finally:
                    os.close(receipt_fd); receipt_fd = None
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        finally:
            if receipt_fd is not None:
                os.close(receipt_fd)
    if state.uncertain:
        receipt.update(status='FAIL',cleanup='FAIL',signal_teardown_uncertain=True)
    if fault is not None or receipt['status'] != 'PASS':
        error = Refused('repository custody launch refused'); error.receipt = receipt
        raise error from fault
    return receipt


@contextmanager
def scoped_executor(module, **options):
    """Restore one explicitly captured CI module's executor on every outcome."""
    identity = id(module)
    original = module.execute_container
    with _LOCK:
        need(identity not in _SCOPES, 'overlapping launch interposition refused')
        _SCOPES.add(identity)
    def executor(command, log, timeout=1800, keep=False):
        names = [command[i+1] for i, item in enumerate(command[:-1]) if item == '--name']
        if not any(name.startswith('cachy-asahi-repository-') for name in names):
            return original(command, log, timeout=timeout, keep=keep)
        need(not keep and 0 < timeout <= 1800, 'repository launch retention/timeout differs')
        launch_options = {key: value for key, value in options.items() if key != 'private_root'}
        launch_options['deadline'] = min(options['deadline'], time.monotonic() + timeout)
        return run_repository(command, log, options['private_root'], original,
                              **launch_options)
    try:
        module.execute_container = executor
        yield executor
        need(module.execute_container is executor, 'scoped executor binding drift')
    finally:
        try:
            module.execute_container = original
        finally:
            with _LOCK:
                _SCOPES.remove(identity)
