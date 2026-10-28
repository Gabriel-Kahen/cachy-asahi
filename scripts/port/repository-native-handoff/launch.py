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

ORIGINAL_PIN = '49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940'
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


class Cancellation:
    def __init__(self):
        self.pending = False
        self.depth = 0

    def handler(self, number, frame):
        self.pending = True
        if not self.depth:
            raise Cancelled('launch cancelled')

    @contextmanager
    def defer(self):
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        self.depth += 1
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
            self.depth -= 1
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            if self.pending and not self.depth:
                raise Cancelled('launch cancelled after cleanup')


@contextmanager
def cancellation_handlers(state):
    need(threading.current_thread() is threading.main_thread(), 'main-thread signal supervision required')
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    original = {number: signal.getsignal(number) for number in SIGNALS}
    error = None
    try:
        for number in SIGNALS:
            signal.signal(number, state.handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        for number, handler in original.items():
            for _ in range(2):
                try:
                    signal.signal(number, handler)
                except BaseException as fault:
                    error = error or fault
                if signal.getsignal(number) == handler:
                    break
        transition = []
        pending = signal.sigpending() & (SIGNALS - set(mask))
        while pending:
            transition.append(signal.sigwait(pending))
            pending = signal.sigpending() & (SIGNALS - set(mask))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if transition:
            state.pending = True
        if error:
            raise error
        if state.pending:
            raise Cancelled('launch cancelled')


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


def inspect_owned(value, expected, *, terminal=False):
    need(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), 'one inspect record required')
    row = value[0]; config, host = row.get('Config', {}), row.get('HostConfig', {})
    need(row.get('Id') == expected['cid'] and row.get('Name') == '/' + expected['name']
         and row.get('Image') == expected['image'], 'container ownership differs')
    required_env = {'CACHY_ASAHI_REPOSITORY_CONTAINER=1', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=' + expected['nonce'],
                    'CACHY_ASAHI_IMAGE_ID=' + expected['image']}
    need(config.get('User') == '0:0' and config.get('OpenStdin') is True and config.get('Tty') is False
         and config.get('Entrypoint') == ['/usr/bin/python3'] and config.get('Cmd') == expected['worker_args']
         and isinstance(config.get('Env'), list) and required_env <= set(config['Env'])
         and all(sum(item.startswith(key) for item in config['Env']) == 1 for key in
                 ('CACHY_ASAHI_REPOSITORY_CONTAINER=', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY=', 'CACHY_ASAHI_IMAGE_ID=')),
         'created producer config differs')
    need(host.get('NetworkMode') == 'none' and host.get('CgroupnsMode') == 'private'
         and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
         and host.get('CapDrop') == ['ALL'] and isinstance(host.get('CapAdd'), list)
         and len(host['CapAdd']) == 6 and set(host['CapAdd']) == set(CAPS)
         and host.get('PidsLimit') == 512 and host.get('Memory') == 8 * 1024**3
         and host.get('NanoCpus') == 4 * 10**9 and host.get('SecurityOpt') == ['no-new-privileges']
         and host.get('Tmpfs') == {'/scratch': 'rw,nosuid,nodev,exec,size=6g,mode=0700',
                                  '/test-home': 'rw,nosuid,nodev,exec,size=128m,mode=0700'}
         and not any(host.get(key) for key in ('Devices', 'DeviceRequests', 'Binds', 'VolumesFrom')),
         'created resource policy differs')
    mounts = row.get('Mounts')
    need(isinstance(mounts, list) and all(isinstance(m, dict) for m in mounts)
         and len({m.get('Destination') for m in mounts}) == len(mounts), 'created mounts malformed')
    binds = [m for m in mounts if m.get('Type') == 'bind']
    need(len(binds) == 3 and {m.get('Destination') for m in binds} == set(expected['binds'])
         and all(m.get('Source') == str(expected['binds'][m['Destination']])
                 and m.get('RW') is (m['Destination'] == '/out') for m in binds)
         and all(m.get('Type') == 'bind' or m.get('Type') == 'tmpfs'
                 and m.get('Destination') in ('/scratch', '/test-home') and m.get('RW') is True
                 and m.get('Source') in ('', None) for m in mounts), 'created bind mounts differ')
    if terminal:
        state = row.get('State', {})
        need(state.get('Status') == 'exited' and state.get('Running') is False and state.get('OOMKilled') is False
             and type(state.get('ExitCode')) is int and state['ExitCode'] == 0 and state.get('Error') == '',
             'producer terminal state differs')
    return row


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
                alive(deadline); value = contract(command) if callable(contract) else contract
                expected = validate_command(command, value); receipt.update(container=expected['name'], image_id=expected['image'], nonce=expected['nonce'])
                root = Path(private_root).absolute()
                with directory(root) as fd:
                    need(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'private custody mode required')
                need(all(root != path and root not in path.parents and path not in root.parents for path in expected['binds'].values()),
                     'custody/mount overlap refused')
                work = root / ('launch-' + expected['nonce']); work.mkdir(mode=0o700)
                if prepare_runner is not None:
                    prepared = prepare_runner(command)
                    need(prepared is None or prepared == producer_pin, 'prepared observer pin differs')
                alive(deadline); validate_command(command, value)
                need(isinstance(producer_pin, str) and re.fullmatch('[0-9a-f]{64}', producer_pin)
                     and digest(read(expected['binds']['/runner'] / 'producer.py')) == producer_pin, 'observer source differs')
                cidfile = work / 'cid'
                image = decode(call(['docker', 'image', 'inspect', expected['image']], deadline))
                need(isinstance(image, list) and len(image) == 1 and image[0].get('Id') == expected['image']
                     and image[0].get('Architecture') == 'arm64' and image[0].get('Os') == 'linux', 'native image differs')
                daemon = call(['docker', 'info', '--format', '{{.Architecture}}'], deadline)
                need(daemon.strip() in (b'arm64', b'aarch64'), 'native daemon required')
                listing = call(['docker', 'container', 'ls', '-a', '--no-trunc', '--filter',
                                'name=^/' + expected['name'] + '$', '--format', '{{.ID}} {{.Names}}'], deadline)
                need(listing == b'', 'repository name already occupied')
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
                inspect_owned(decode(call(['docker', 'container', 'inspect', cid], deadline)), expected)
                receipt['ownership_verified'] = True
                protocol = Protocol(expected['nonce'], checkpoint_handler, deadline)
                argv = ['docker', 'start', '--attach', '--interactive', cid]
                response = run.attach(argv, on_stdout=protocol.feed, on_stdin=protocol.stdin, deadline=deadline, limit=2*LIMIT+4*1024**2)
                record(argv, response, 2*LIMIT+4*1024**2); alive(deadline)
                need(response['exit_code'] == 0 and RESERVED not in response['stderr']
                     and response['stdout'] == bytes(protocol.raw), 'attach failed or raw callback stream differs')
                protocol.finish(); receipt['checkpoints'] = protocol.frames
                inspect_owned(decode(call(['docker', 'container', 'inspect', cid], deadline)), expected, terminal=True)
                need(b'PASS: disposable generic repository transactions; hardware/stable gates unchanged.' in protocol.plain,
                     'original producer PASS missing')
                need(digest(read(expected['binds']['/runner'] / 'repository.py')) == ORIGINAL_PIN
                     and digest(read(expected['binds']['/runner'] / 'producer.py')) == producer_pin
                     and digest(read(expected['binds']['/inputs'] / 'manifest.json')) == command[-2],
                     'source or contract drift after producer')
                receipt['status'] = 'PASS'
            except BaseException as error:
                fault = error; receipt['error_type'] = type(error).__name__
            finally:
                if submitted:
                    try:
                        with state.defer():
                            cleanup_end = time.monotonic() + 30
                            if 'cid' not in expected:
                                receipt['ownership_uncertain'] = True; receipt['status'] = 'FAIL'
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
                                inspect_owned(decode(call(['docker', 'container', 'inspect', expected['cid']], cleanup_end)), expected)
                            call(['docker', 'container', 'rm', '-f', expected['cid']], cleanup_end)
                            listing = call(['docker', 'container', 'ls', '-a', '--no-trunc', '--format', '{{.ID}} {{.Names}}'], cleanup_end)
                            rows = [line.split() for line in listing.decode().splitlines()]
                            need(all(len(row) == 2 and re.fullmatch('[0-9a-f]{64}', row[0]) for row in rows), 'absence query malformed')
                            receipt['name_absence_verified'] = all(expected['name'] not in row[1].split(',') for row in rows)
                            receipt['id_absence_verified'] = all(expected['cid'] != row[0] for row in rows)
                            receipt['absence_verified'] = receipt['name_absence_verified'] and receipt['id_absence_verified']
                            need(receipt['absence_verified'], 'name or ID remains')
                            receipt['cleanup'] = 'PASS'
                    except BaseException as error:
                        fault = fault or error; receipt['status'] = 'FAIL'; receipt['cleanup_error_type'] = type(error).__name__
    except BaseException as error:
        fault = fault or error; receipt['status'] = 'FAIL'; receipt['error_type'] = type(error).__name__
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
                    with directory(work) as parent:
                        receipt_fd = os.open('receipt.json', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                             0o600, dir_fd=parent)
                        os.fsync(parent)
                    write_new(log, bytes(protocol.plain) if protocol is not None else b'')
                    write_new(Path(log).with_suffix('.cleanup.json'), encoded(dict(summary, status=receipt['cleanup'])) + b'\n')
                    write_new(Path(log).with_suffix('.launcher.json'), encoded({'status': receipt['status']}) + b'\n')
                    if state.pending:
                        receipt.update(status='FAIL', cancelled=True)
                    commit()
                    if state.pending:
                        receipt.update(status='FAIL', cancelled=True); commit()
        except BaseException as error:
            fault = fault or error; receipt['status'] = 'FAIL'; receipt['publication_error_type'] = type(error).__name__
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
