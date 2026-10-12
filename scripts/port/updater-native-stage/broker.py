#!/usr/bin/env python3
"""Private, nonce-scoped Docker broker. Never invoke against an unpinned daemon.

The controller owns the private registry. Intents precede mutations; cleanup
removes only individually inspected nonce-labelled resources. A build without
an authenticated final iidfile is ambiguous, never a successful cleanup.
"""
from contextlib import contextmanager
import fcntl
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
import sys
import tempfile
import threading
import time
import uuid

LABEL = 'cachy-asahi.updater-stage'
CONTROLLER_ENV = 'CACHY_ASAHI_BROKER_CONTROLLER'
CONTROLLER_HASH_ENV = 'CACHY_ASAHI_BROKER_CONTROLLER_SHA256'
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
WORKER = re.compile(r'cachy-asahi-updater-([0-9a-f]{32})')
QUERY_BYTES = 1024 * 1024
COMMAND_SECONDS = 1800
PROC_ROOT = Path('/proc')


class BrokerError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(value, code):
    if not value:
        raise BrokerError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(BrokerError('json-number')))


def regular(path, limit=QUERY_BYTES, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'bounded-regular-file')
        need(not stat.S_IMODE(before.st_mode) & 0o022, 'writable-file')
        need(not stat.S_IMODE(before.st_mode) & 0o7000, 'special-file-mode')
        if private:
            need(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600, 'private-file-owner-mode')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        need(len(data) == before.st_size and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file-drift')
        return data
    finally:
        os.close(fd)


def root_path(value):
    root = Path(value)
    need(root.is_absolute() and root.is_relative_to('/tmp') and '..' not in root.parts and root.resolve(strict=True) == root, 'private-root-path')
    info = root.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private-root-owner-mode')
    return root


def under(c, value, exists=True):
    path = Path(value)
    root = Path(c['root'])
    need(path.is_absolute() and path.is_relative_to(root) and path != root and '..' not in path.parts, 'path-outside-root')
    for parent in reversed(path.parents):
        if parent == root or parent.is_relative_to(root):
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe-owned-parent')
    if exists:
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid() and
             (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) and not stat.S_IMODE(info.st_mode) & 0o022, 'unsafe-owned-path')
    else:
        need(not path.exists() and not path.is_symlink(), 'nonfresh-owned-path')
    return path


def load_controller(path, expected, allow_expired=False):
    need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0, 'ordinary-user-required')
    need(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected), 'controller-pin')
    data = regular(path, private=True)
    need(sha(data) == expected, 'controller-pin-drift')
    c = load(data)
    need(type(c) is dict and set(c) == {'schema_version', 'nonce', 'root', 'real_docker', 'real_docker_sha256', 'docker_endpoint', 'docker_socket_identity', 'deadline_monotonic'}, 'controller-schema')
    need(type(c['schema_version']) is int and c['schema_version'] == 1 and
         type(c['nonce']) is str and re.fullmatch('[0-9a-f]{32}', c['nonce']), 'controller-identity')
    root_path(c['root'])
    under(c, str(path))
    need(c['docker_endpoint'] in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'), 'fixed-local-endpoint')
    need(type(c['deadline_monotonic']) in (int, float) and math.isfinite(c['deadline_monotonic']) and
         c['deadline_monotonic'] <= time.monotonic() + 7200 and (allow_expired or c['deadline_monotonic'] > time.monotonic()), 'controller-deadline')
    docker = Path(c['real_docker'])
    need(docker.is_absolute() and docker.resolve(strict=True) == docker and
         type(c['real_docker_sha256']) is str and re.fullmatch('[0-9a-f]{64}', c['real_docker_sha256']), 'docker-executable-path')
    need(docker.stat().st_mode & 0o111 and sha(regular(docker, 64 * 1024**2)) == c['real_docker_sha256'], 'docker-executable-pin')
    c['_path'], c['_sha256'] = str(path), expected
    socket_identity(c)
    return c


def socket_info(path):
    return os.stat(path, follow_symlinks=False)


def socket_identity(c):
    expected = c['docker_socket_identity']
    need(type(expected) is dict and set(expected) == {'device', 'inode'} and
         all(type(value) is int and value >= 0 for value in expected.values()), 'socket-identity-schema')
    info = socket_info(c['docker_endpoint'][7:])
    need(stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == (expected['device'], expected['inode']), 'socket-identity-changed')


def client_identity(pid):
    need(type(pid) is int and pid > 1, 'client-pid')
    directory = PROC_ROOT / str(pid)
    with (directory / 'stat').open('rb') as stream: raw = stream.read(4097)
    need(len(raw) <= 4096, 'client-stat-bound')
    fields = raw.rsplit(b')', 1)[1].split()
    uid = directory.stat().st_uid
    group, session, start = int(fields[2]), int(fields[3]), int(fields[19])
    need(uid == os.getuid() and group == session == pid and start > 0, 'client-session-identity')
    return {'pid': pid, 'pgid': group, 'start_ticks': start, 'uid': uid}


def group_absent(pgid):
    try: os.killpg(pgid, 0)
    except ProcessLookupError: return True
    except PermissionError: return False
    return False


def reap_client(row, expected):
    """Reap only this authenticated positive PID, if it is our adopted child."""
    need(client_identity(row['pid']) == expected, 'client-generation-changed')
    try: pid, _ = os.waitpid(row['pid'], os.WNOHANG)
    except ChildProcessError: return 'NOT_CHILD'
    need(pid in (0, row['pid']), 'client-reap-identity')
    return 'REAPED' if pid else 'LIVE'


def terminate_client(row, deadline):
    """Never signal a reused leader or a leaderless surviving group."""
    if group_absent(row['pgid']): return True
    try: current = client_identity(row['pid'])
    except (OSError, ValueError, IndexError): return False
    if current != {key: row[key] for key in ('pid', 'pgid', 'start_ticks', 'uid')}: return False
    for signum, seconds in ((signal.SIGTERM, 2), (signal.SIGKILL, 3)):
        if group_absent(row['pgid']): return True
        try:
            need(client_identity(row['pid']) == current, 'client-generation-changed')
            os.killpg(row['pgid'], signum)
        except ProcessLookupError: return group_absent(row['pgid'])
        except (OSError, ValueError, IndexError): return False
        end = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < end:
            if group_absent(row['pgid']): return True
            try: reap_client(row, current)
            except (FileNotFoundError, ProcessLookupError): return group_absent(row['pgid'])
            except (OSError, ValueError, IndexError): return False
            if group_absent(row['pgid']): return True
            time.sleep(.05)
    return group_absent(row['pgid'])


def save(path, value):
    fd, name = tempfile.mkstemp(prefix='.broker-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')
            stream.flush();os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: os.unlink(name)
        except FileNotFoundError: pass


@contextmanager
def registry(c, deadline, signals=None, honor_cancel=True):
    root = Path(c['root'])
    lock = root / 'broker.lock'
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600, 'registry-lock-owner')
        while True:
            if honor_cancel and signals is not None: need(not signals.seen, 'cancelled')
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB);break
            except BlockingIOError:
                need(time.monotonic() < deadline, 'registry-lock-deadline');time.sleep(.05)
        path = root / 'broker-registry.json'
        if path.exists() or path.is_symlink():
            data = load(regular(path, private=True))
            need(type(data) is dict and data.get('schema_version') == 1 and data.get('nonce') == c['nonce'] and
                 data.get('controller_sha256') == c['_sha256'] and data.get('controller_path') == c['_path'] and
                 data.get('docker_socket_identity') == c['docker_socket_identity'], 'registry-binding')
            need(type(data.get('containers')) is list and len(data['containers']) <= 32 and
                 type(data.get('builds')) is list and len(data['builds']) <= 8 and
                 type(data.get('invocations')) is list and len(data['invocations']) <= 512 and
                 type(data.get('clients')) is list and len(data['clients']) <= 2048, 'registry-bounds')
        else:
            data = {'schema_version': 1, 'nonce': c['nonce'], 'controller_path': c['_path'], 'controller_sha256': c['_sha256'],
                    'docker_socket_identity': c['docker_socket_identity'],
                    'containers': [], 'builds': [], 'invocations': [], 'clients': []}
        names, iids = set(), set()
        for row in data['containers']:
            need(type(row) is dict and set(row) == {'name', 'image_id', 'status'} and type(row['name']) is str and
                 (WORKER.fullmatch(row['name']) or re.fullmatch(r'cachy-asahi-stage-' + c['nonce'] + r'-[0-9a-f]{32}', row['name'])) and
                 IMAGE.fullmatch(row['image_id']) and row['status'] in ('INTENT', 'PASS', 'FAIL') and row['name'] not in names, 'registry-container')
            names.add(row['name'])
        for row in data['builds']:
            need(type(row) is dict and set(row) <= {'iidfile', 'image_id', 'status', 'absence_verified'} and
                 {'iidfile', 'image_id', 'status'} <= set(row) and type(row['iidfile']) is str and
                 Path(row['iidfile']).is_relative_to(root) and row['iidfile'] not in iids and
                 (row['image_id'] is None or type(row['image_id']) is str and IMAGE.fullmatch(row['image_id'])) and
                 row['status'] in ('INTENT', 'PASS', 'FAIL') and type(row.get('absence_verified', False)) is bool, 'registry-build')
            iids.add(row['iidfile'])
        for row in data['clients']:
            need(type(row) is dict and set(row) == {'pid', 'pgid', 'start_ticks', 'uid', 'status'} and
                 type(row['uid']) is int and row['uid'] == os.getuid() and row['status'] in ('INTENT', 'LIVE', 'ABSENT', 'NOT_STARTED', 'AMBIGUOUS') and
                 (row['pid'] is None and row['pgid'] is None and row['start_ticks'] is None or
                  type(row['pid']) is int and row['pid'] > 1 and row['pgid'] == row['pid'] and
                  (row['start_ticks'] is None or type(row['start_ticks']) is int and row['start_ticks'] > 0)), 'registry-client')
        def client_intent():
            need(len(data['clients']) < 2048, 'client-count')
            row = {'pid': None, 'pgid': None, 'start_ticks': None, 'uid': os.getuid(), 'status': 'INTENT'}
            data['clients'].append(row);save(path, data)
            return row
        def client_started(row, pid):
            row.update(pid=pid, pgid=pid, status='AMBIGUOUS');save(path, data)
            row.update(client_identity(pid), status='LIVE');save(path, data)
        def client_done(row, started):
            row['status'] = ('ABSENT' if group_absent(row['pgid']) else 'AMBIGUOUS') if started else 'NOT_STARTED'
            save(path, data)
            need(row['status'] != 'AMBIGUOUS', 'client-group-ambiguous')
        c['_client_intent'], c['_client_started'], c['_client_done'] = client_intent, client_started, client_done
        yield data, lambda: save(path, data)
    finally:
        os.close(fd)


class Signals:
    def __enter__(self):
        need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1, 'single-threaded-broker-required')
        self.seen = []
        self.signals = {signal.SIGTERM, signal.SIGINT}
        if signal.getsignal(signal.SIGALRM) not in (signal.SIG_DFL, signal.SIG_IGN): self.signals.add(signal.SIGALRM)
        self.previous = {s: signal.getsignal(s) for s in self.signals}
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        try:
            for s in self.signals: signal.signal(s, self.defer)
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, prior)
        return self

    def defer(self, signum, frame):
        if not self.seen: self.seen.append(signum)

    def __exit__(self, *args):
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        try:
            pending = signal.sigpending() & self.signals
            if pending and not self.seen: self.seen.append(int(next(iter(pending))))
            for s, handler in self.previous.items(): signal.signal(s, handler)
        finally:
            try: signal.pthread_sigmask(signal.SIG_SETMASK, prior)
            except BaseException:
                if not self.seen: self.seen.append(signal.SIGTERM)


def execute(c, args, signals, capture=False, seconds=COMMAND_SECONDS, honor_cancel=True):
    deadline = min(c['deadline_monotonic'], time.monotonic() + seconds)
    need(time.monotonic() < deadline, 'command-deadline')
    if honor_cancel: need(not signals.seen, 'cancelled')
    socket_identity(c)
    need(sha(regular(Path(c['real_docker']), 64 * 1024**2)) == c['real_docker_sha256'], 'docker-executable-pin')
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8', 'HOME': c['root'], 'DOCKER_CONFIG': str(Path(c['root']) / 'docker-config'),
           'DOCKER_HOST': c['docker_endpoint']}
    if args[:2] == ['context', 'inspect']: env['DOCKER_CONTEXT'] = 'default'
    command = [c['real_docker'], '--host', c['docker_endpoint'], *args]
    need(all(key in c for key in ('_client_intent', '_client_started', '_client_done')), 'client-registry-required')
    client = c['_client_intent']()
    process, output = None, bytearray()
    try:
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, signals.signals)
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.DEVNULL if capture else None, env=env, start_new_session=True,
                preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, prior))
            c['_client_started'](client, process.pid)  # Durable generation before unmask/wait.
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, prior)
        with selectors.DefaultSelector() as selector:
            if capture:
                os.set_blocking(process.stdout.fileno(), False);selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if honor_cancel: need(not signals.seen, 'cancelled')
                need(time.monotonic() < deadline, 'command-deadline')
                for key, _ in selector.select(.1) if capture else []:
                    chunk = os.read(key.fd, 65536)
                    if not chunk: selector.unregister(key.fileobj)
                    output.extend(chunk);need(len(output) <= QUERY_BYTES, 'query-output-bound')
                if process.poll() is not None and (not capture or not selector.get_map()): break
                if not capture:
                    try: process.wait(timeout=.1)
                    except subprocess.TimeoutExpired: pass
        return process.returncode, bytes(output)
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    # This unreaped child was created by this Popen. Immediate
                    # cleanup must not depend on a registry callback succeeding.
                    try: os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                process.wait(timeout=3)
                if process.stdout is not None: process.stdout.close()
        finally: c['_client_done'](client, process is not None)


def query(c, args, signals, honor_cancel=True):
    code, data = execute(c, args, signals, capture=True, seconds=60, honor_cancel=honor_cancel)
    need(code == 0 and len(data) <= QUERY_BYTES, 'docker-query-failed')
    return data


def image_owned(c, image, signals, honor_cancel=True):
    need(type(image) is str and IMAGE.fullmatch(image), 'image-id')
    rows = load(query(c, ['image', 'inspect', image], signals, honor_cancel))
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and rows[0].get('Id') == image and
         type(rows[0].get('Config')) is dict and type(rows[0]['Config'].get('Labels')) is dict and
         rows[0]['Config']['Labels'].get(LABEL) == c['nonce'], 'image-label-mismatch')


def container_absent(c, name, signals, honor_cancel=True):
    need(type(name) is str and (WORKER.fullmatch(name) or re.fullmatch(r'cachy-asahi-stage-' + c['nonce'] + r'-[0-9a-f]{32}', name)), 'owned-container-name')
    return not query(c, ['ps', '--all', '--filter=name=^/' + name + '$', '--format={{.ID}}'], signals, honor_cancel).strip()


def container_owned(c, name, signals, honor_cancel=True):
    rows = load(query(c, ['inspect', name], signals, honor_cancel))
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and rows[0].get('Name') == '/' + name and
         type(rows[0].get('Config')) is dict and type(rows[0]['Config'].get('Labels')) is dict and
         rows[0]['Config']['Labels'].get(LABEL) == c['nonce'], 'container-label-mismatch')


def image_ids(data):
    return {row['image_id'] for row in data['builds'] if row.get('image_id')}


def mounts(c, values, name, image, env):
    found = {}
    for value in values:
        parts = value.split(',')
        need(len(parts) in (3, 4) and parts[0] == 'type=bind' and parts[1].startswith('src=') and parts[2].startswith('dst='), 'mount-schema')
        source = under(c, parts[1][4:]);target = parts[2][4:]
        need(target not in found and target in ('/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'), 'mount-target')
        need((len(parts) == 3 and target == '/out') or (len(parts) == 4 and parts[3] == 'readonly' and target != '/out'), 'mount-access')
        found[target] = source
    need(set(found) == {'/inputs', '/out', '/builder-entry.sh', '/expected-packages.lock'}, 'mount-set')
    raw = regular(found['/inputs'] / 'controller-input.json')
    controller = load(raw)
    nonce = WORKER.fullmatch(name)[1]
    need(controller.get('nonce') == nonce and controller.get('image_id') == image and
         env == {'CACHY_ASAHI_CONTAINER': '1', 'CACHY_ASAHI_IMAGE_ID': image, 'CACHY_ASAHI_UPDATE_BUILD_NONCE': nonce,
                 'CACHY_ASAHI_CONTROLLER_SHA256': sha(raw), 'SOURCE_DATE_EPOCH': '1789753605'}, 'worker-controller-binding')
    need(sha(regular(found['/builder-entry.sh'])) == controller.get('entry_script_sha256') and
         sha(regular(found['/expected-packages.lock'])) == controller.get('builder_inventory_sha256'), 'worker-readonly-input-binding')


def plan(c, args, data):
    need(type(args) is list and 1 <= len(args) <= 96 and all(type(a) is str and 0 < len(a) <= 4096 and '\x00' not in a and '\n' not in a for a in args), 'docker-argv')
    if args in (['info', '--format', '{{.Architecture}}'], ['info', '--format', '{{json .}}'], ['version'], ['context', 'inspect']): return args, None
    if args[:1] == ['build']:
        need(len(args) == 7 and args[1:4] == ['--network=none', '--pull=false', '--platform=linux/arm64'] and args[4] == '--iidfile', 'docker-build-shape')
        iid = under(c, args[5], exists=False);context = under(c, args[6]);regular(context / 'Dockerfile', 1024**2)
        need(not any(row['iidfile'] == str(iid) for row in data['builds']), 'build-iid-claim')
        row = {'iidfile': str(iid), 'image_id': None, 'status': 'INTENT'}
        return ['build', '--label', LABEL + '=' + c['nonce'], *args[1:]], ('build', row)
    if args[:1] == ['run']:
        need(len(data['containers']) < 32, 'container-count')
        if args[1:8] == ['--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat']:
            need(len(args) == 10 and args[-1] == '/builder-packages.lock' and args[-2] in image_ids(data), 'inventory-run-shape')
            name = 'cachy-asahi-stage-' + c['nonce'] + '-' + uuid.uuid4().hex
            return ['run', '--name', name, '--label', LABEL + '=' + c['nonce'], *args[1:]], ('container', {'name': name, 'image_id': args[-2], 'status': 'INTENT'})
        need(len(args) >= 5 and args[1] == '--name' and WORKER.fullmatch(args[2]), 'worker-name')
        name, options, env, binds, index = args[2], {}, {}, [], 3
        while index < len(args) and args[index].startswith('--'):
            token = args[index]
            if token in ('--user', '--mount'):
                need(index + 1 < len(args), 'worker-option-value');value = args[index + 1];index += 2
                if token == '--mount': binds.append(value);continue
                key = token
            else:
                key, separator, value = token.partition('=');index += 1
                if key == '--env':
                    k, sep, v = value.partition('=');need(separator and sep and k not in env, 'worker-env');env[k] = v;continue
                if token == '--read-only': key, value = token, True
            need(key not in options, 'worker-option-duplicate');options[key] = value
        need(args[index:] and len(args[index:]) == 2 and args[index + 1] == '/builder-entry.sh', 'worker-command')
        image = args[index];need(image in image_ids(data), 'unowned-worker-image')
        need(options == {'--pull': 'never', '--platform': 'linux/arm64', '--user': f'{os.getuid()}:{os.getgid()}', '--cap-drop': 'ALL',
            '--security-opt': 'no-new-privileges', '--read-only': True, '--pids-limit': '512', '--memory': '4g', '--cpus': '4',
            '--network': 'none', '--tmpfs': '/tmp:rw,nosuid,nodev,exec,size=4g', '--entrypoint': '/usr/bin/python'}, 'worker-option-set')
        mounts(c, binds, name, image, env)
        need(not any(row['name'] == name for row in data['containers']), 'container-name-claim')
        return ['run', '--label', LABEL + '=' + c['nonce'], *args[1:]], ('container', {'name': name, 'image_id': image, 'status': 'INTENT'})
    owned = {row['name'] for row in data['containers']}
    if args[:2] == ['image', 'inspect']:
        need(len(args) == 3 and args[2] in image_ids(data), 'image-inspect-scope');return args, None
    if args[:1] == ['inspect']:
        need(len(args) == 2 and args[1] in owned, 'container-inspect-scope');return args, None
    if args[:1] == ['rm']:
        need(len(args) == 3 and args[1] in ('-f', '--force') and args[2] in owned, 'container-remove-scope');return args, ('remove', args[2])
    if args[:2] == ['ps', '--all']:
        need(len(args) == 4 and args[2] in {'--filter=name=^/' + name + '$' for name in owned} and args[3] == '--format={{.ID}}', 'container-list-scope');return args, None
    raise BrokerError('unsupported-docker-command')


def invoke(controller, args):
    c = load_controller(controller['_path'], controller['_sha256'])
    with Signals() as signals:
        with registry(c, c['deadline_monotonic'], signals) as (data, persist):
            rewritten, resource = plan(c, args, data)
            need(len(data['invocations']) < 512, 'invocation-count')
            record = {'command': args[0], 'status': 'INTENT'};data['invocations'].append(record)
            persist()
            if resource:
                kind, row = resource
                if kind == 'container':
                    need(container_absent(c, row['name'], signals), 'container-name-already-exists')
                    image_owned(c, row['image_id'], signals);data['containers'].append(row)
                elif kind == 'build': need(len(data['builds']) < 8, 'build-count');data['builds'].append(row)
                elif kind == 'remove' and not container_absent(c, row, signals): container_owned(c, row, signals)
            if args[:2] == ['image', 'inspect']: image_owned(c, args[2], signals)
            if args[:1] == ['inspect']: container_owned(c, args[1], signals)
            persist()  # Durable resource intent before any mutating command.
            try:
                seconds = COMMAND_SECONDS if args[0] == 'build' or args[0] == 'run' and '--rm' not in args else 60
                code, _ = execute(c, rewritten, signals, seconds=seconds)
                record.update(status='PASS' if code == 0 else 'FAIL', exit_code=code)
                if resource and resource[0] == 'build':
                    row = resource[1]
                    need(code != 0 or Path(row['iidfile']).exists(), 'build-iid-missing')
                    if Path(row['iidfile']).exists():
                        image = regular(row['iidfile'], 128).decode('ascii').strip();need(IMAGE.fullmatch(image), 'build-iid-invalid')
                        row['image_id'] = image;image_owned(c, image, signals)
                        row['status'] = 'PASS' if code == 0 else 'FAIL'
                if resource and resource[0] == 'container': resource[1]['status'] = 'PASS' if code == 0 else 'FAIL'
            except BaseException as error:
                record.update(status='FAIL', failure_code=error.code if isinstance(error, BrokerError) else 'command-exception')
                persist();raise
            finally: persist()
    if signals.seen: return 128 + int(signals.seen[0])
    return code


def _cleanup(root, nonce, realDocker, endpoint, deadline):
    root = root_path(str(root))
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline <= time.monotonic() + 600, 'cleanup-deadline')
    registry_path = root / 'broker-registry.json'
    if not registry_path.exists() and not registry_path.is_symlink():
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce), 'cleanup-nonce')
        return {'schema_version': 1, 'status': 'PASS', 'registry_state': 'EMPTY', 'failures': [], 'containers_absent': 0, 'images_absent': 0, 'clients_absent': 0}
    initial = load(regular(registry_path, private=True))
    c = load_controller(initial['controller_path'], initial['controller_sha256'], allow_expired=True)
    need(c['root'] == str(root) and c['nonce'] == nonce and c['real_docker'] == str(realDocker) and c['docker_endpoint'] == endpoint, 'cleanup-controller-binding')
    c['deadline_monotonic'] = deadline
    receipt = {'schema_version': 1, 'status': 'FAIL', 'failures': [], 'containers_absent': 0, 'images_absent': 0, 'clients_absent': 0}
    with Signals() as signals:
        with registry(c, deadline, signals, honor_cancel=False) as (data, persist):
            for row in list(data['clients']):
                if row['status'] in ('NOT_STARTED', 'ABSENT'): receipt['clients_absent'] += 1;continue
                if row['pid'] is None:
                    receipt['failures'].append('client-launch-ambiguous');continue
                if terminate_client(row, deadline):
                    row['status'] = 'ABSENT';receipt['clients_absent'] += 1
                else: receipt['failures'].append('client-group-ambiguous')
            persist()
            for row in data['containers']:
                try:
                    name = row['name']
                    if not container_absent(c, name, signals, False):
                        container_owned(c, name, signals, False)
                        query(c, ['rm', '--force', name], signals, False)
                    need(container_absent(c, name, signals, False), 'container-remains')
                    receipt['containers_absent'] += 1
                except (OSError, ValueError, KeyError): receipt['failures'].append('container-cleanup-unverified')
            for row in data['builds']:
                try:
                    iid = under(c, row['iidfile'])
                    image = regular(iid, 128).decode('ascii').strip();need(IMAGE.fullmatch(image), 'build-iid-invalid')
                    need(row.get('image_id') in (None, image), 'build-iid-drift')
                    if not row.get('absence_verified'):
                        image_owned(c, image, signals, False)
                        query(c, ['rmi', image], signals, False)
                    # Docker image inspect failure alone is not absence proof.
                    lines = query(c, ['image', 'ls', '--no-trunc', '--filter=label=' + LABEL + '=' + c['nonce'], '--format={{.ID}}'], signals, False).decode('ascii').splitlines()
                    ids = set()
                    for value in lines:
                        normalized = value if value.startswith('sha256:') else 'sha256:' + value
                        need(IMAGE.fullmatch(normalized), 'image-list-schema');ids.add(normalized)
                    need(image not in ids, 'image-remains')
                    row['absence_verified'] = True
                    receipt['images_absent'] += 1
                except (OSError, ValueError, KeyError): receipt['failures'].append('image-cleanup-ambiguous')
            persist()
    if signals.seen: receipt['failures'].append('cleanup-cancelled')
    receipt['status'] = 'PASS' if not receipt['failures'] else 'FAIL'
    save(root / 'broker-cleanup.json', receipt)
    return receipt


def cleanup(root, nonce, realDocker, endpoint, deadline):
    """Typed failure on validation/daemon ambiguity; never remove outside scope."""
    try:
        return _cleanup(root, nonce, realDocker, endpoint, deadline)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return {'schema_version': 1, 'status': 'FAIL', 'failures': ['cleanup-validation-or-daemon-failure'],
                'containers_absent': 0, 'images_absent': 0, 'clients_absent': 0}


if __name__ == '__main__':
    try:
        c = load_controller(os.environ.get(CONTROLLER_ENV, ''), os.environ.get(CONTROLLER_HASH_ENV, ''))
        code = invoke(c, sys.argv[1:])
    except (OSError, ValueError, KeyError):
        print('Docker broker rejected invocation or command failed; private registry retained.', file=sys.stderr)
        code = 1
    raise SystemExit(code)
