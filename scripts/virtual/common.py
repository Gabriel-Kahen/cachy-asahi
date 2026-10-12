#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fail-closed contracts for the disposable generic ARM guest proof."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
from contextlib import contextmanager

GIB = 1024 ** 3
MAX_LOG = 64 * 1024 ** 2
OVERLAYS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
            'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
SAFE_CAPS = (1 << 0) | (1 << 1) | (1 << 3) | (1 << 4)  # CHOWN/DAC_OVERRIDE/FOWNER/FSETID, fixture metadata only
IMAGE_SHA = '92445dac35421e6cba8ccf7b3e7de8fe8ca8914b69db26fce4a5162352f5dc0a'
KERNEL = '7.2.10-1-aarch64-ARCH'
QEMU_COMMIT = '4fc49f46dc95d4a27de2509e7fceb2931e91faeb'


class Refused(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Refused(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def json_load(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(value):
        raise Refused('nonfinite JSON')
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_constant=constant)


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and
            all(x not in ('', '.', '..') for x in value.split('/')) and
            not any(ord(x) < 32 or ord(x) == 127 for x in value), 'unsafe relative path')
    return value


def pinned(root, name, sha):
    path = Path(root) / relative(name)
    require(re.fullmatch('[0-9a-f]{64}', sha or ''), 'invalid digest')
    require(all(not p.is_symlink() for p in (path, *path.parents)), 'symlink input')
    require(path.is_file() and path.stat().st_nlink == 1, 'regular singly linked input required')
    require(digest(path) == sha, f'input hash differs: {name}')
    return path


def inventory(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in result, 'invalid package inventory')
        result[fields[0]] = fields[1]
    require(result, 'empty inventory')
    return result


def mounts(text):
    result = {}
    for row in text.splitlines():
        before, after = row.split(' - ', 1)
        fields = before.split()
        point = re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])
        result[point] = {'flags': fields[5].split(','), 'type': after.split()[0]}
    return result


def facts():
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    marker = Path('/.dockerenv')
    return {'uid': os.geteuid(), 'arch': platform.machine(),
            'docker': marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0,
            'caps': {k: int(status[k].strip(), 16) for k in ('CapEff', 'CapPrm', 'CapBnd')},
            'nnp': status['NoNewPrivs'].strip(),
            'mounts': mounts(Path('/proc/self/mountinfo').read_text()),
            'interfaces': sorted(x.name for x in Path('/sys/class/net').iterdir()),
            'devices': any(Path(x).exists() for x in ('/dev/dri', '/dev/input', '/dev/snd', '/dev/kvm', '/dev/fuse', '/dev/mem')) or
                       any(stat.S_ISBLK(x.lstat().st_mode) for x in Path('/dev').rglob('*') if not x.is_symlink()),
            'docker_socket': any(Path(x).exists() for x in ('/run/docker.sock', '/var/run/docker.sock')),
            'nonce': os.getenv('CACHY_ASAHI_VIRTUAL_NONCE', ''),
            'image_id': os.getenv('CACHY_ASAHI_IMAGE_ID', ''),
            'marker': os.getenv('CACHY_ASAHI_DISPOSABLE_VIRTUAL', ''),
            'runner': str(Path(__file__).resolve().parent)}


def validate_environment(f, preparation=False):
    require(f['marker'] == '1' and f['docker'] and f['arch'] == 'aarch64', 'explicit disposable native ARM Docker required')
    require((f['uid'] == 0) == preparation, 'root is permitted only for fixture preparation')
    require(not preparation or f['caps']['CapEff'] == SAFE_CAPS, 'preparation requires exact metadata-only capabilities')
    require(f['nnp'] == '1' and not any(v & ~(SAFE_CAPS if preparation else 0) for v in f['caps'].values()), 'privileged capabilities refused')
    require(f['interfaces'] == ['lo'] and not f['devices'] and not f['docker_socket'], 'network/host-device/socket exposure refused')
    require(re.fullmatch('[0-9a-f]{32}', f['nonce']) and re.fullmatch('sha256:[0-9a-f]{64}', f['image_id']), 'nonce/immutable installed-image identity required')
    require(f['runner'] == '/runner/virtual', 'fixed read-only runner location required')
    table = f['mounts']
    for path, flag, kind in (('/', 'ro', None), ('/inputs', 'ro', None), ('/runner', 'ro', None), ('/out', 'rw', None), ('/tmp', 'rw', 'tmpfs')):
        entry = table.get(path, {})
        require(flag in entry.get('flags', []) and (not kind or entry.get('type') == kind), 'required isolated mount absent: ' + path)
    require(table['/']['type'] in ('overlay', 'fuse-overlayfs'), 'disposable overlay root required')
    for path in table:
        require(not any(path.startswith(x + '/') for x in ('/inputs', '/runner', '/out', '/tmp')), 'nested work/input mount refused')
        if any(path == x or path.startswith(x + '/') for x in ('/usr', '/etc', '/var', '/home', '/root', '/run', '/boot')):
            require(path in ('/etc/hosts', '/etc/hostname', '/etc/resolv.conf'), 'host system-path mount refused')


def guard(preparation=False):
    f = facts()
    validate_environment(f, preparation)
    require(not any(os.getenv(x) for x in ('DISPLAY', 'WAYLAND_DISPLAY', 'WAYLAND_SOCKET', 'DBUS_SESSION_BUS_ADDRESS', 'PULSE_SERVER', 'PIPEWIRE_REMOTE')), 'inherited host connection refused')
    return f


def contract(path, sha, f):
    require(path.parent == Path('/inputs') and not path.is_symlink(), 'contract must be directly below /inputs')
    c = json_load(pinned('/inputs', path.name, sha))
    require(c.get('schema_version') == 1 and c.get('execution') == 'qemu-tcg-generic-aarch64', 'unsupported proof contract')
    require(c.get('nonce') == f['nonce'] and c.get('image_id') == f['image_id'], 'contract image/nonce differs')
    require(re.fullmatch('[0-9a-f]{40}', c.get('source_commit', '')), 'reviewed source commit required')
    require(isinstance(c.get('output_uid'), int) and isinstance(c.get('output_gid'), int) and
            1000 <= c['output_uid'] < 60000 and 1000 <= c['output_gid'] < 60000, 'bounded controller UID/GID required')
    rows = c.get('baseline')
    require(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == OVERLAYS, 'all four original overlay archives required')
    for row in rows:
        require(isinstance(row.get('version'), str) and re.fullmatch('[A-Za-z0-9._+:~-]+', row['version']), 'invalid original version')
        pinned('/inputs', row['archive'], row['sha256'])
        require(isinstance(row.get('payload_sha256'), dict) and row['payload_sha256'], 'original complete payload map required')
        for name, value in row['payload_sha256'].items():
            require(relative(name).startswith('usr/') and re.fullmatch('[0-9a-f]{64}', value), 'invalid original payload map')
    receipt = json_load(pinned('/inputs', c['baseline_handoff'], c['baseline_handoff_sha256']))
    require(receipt.get('status') == 'PASS' and receipt.get('baseline_handoff_ready') is True,
            'successful original installed-image handoff required')
    require(receipt.get('handoff_package_versions') == {r['name']: r['version'] for r in rows} and
            receipt.get('handoff_payload_sha256') == {r['name']: r['payload_sha256'] for r in rows}, 'handoff originals differ')
    return c


def check_runtime(c):
    base = inventory(pinned('/inputs', c['base_runtime_lock'], c['base_runtime_lock_sha256']).read_text())
    tooling = json_load(pinned('/inputs', c['tooling_lock'], c['tooling_lock_sha256']))
    require(len(base) == 341 and tooling.get('base_package_count') == 341 and tooling.get('expected_package_count') == 362 and
            tooling.get('qemu_source_commit') == QEMU_COMMIT, 'wrong frozen base/tooling extension')
    audit = json_load(pinned('/inputs', c['tooling_audit'], c['tooling_audit_sha256']))
    require(audit.get('status') == 'PASS' and audit.get('tooling_lock_sha256') == c['tooling_lock_sha256'] and
            set(audit.get('packages', {})) == {r['name'] for r in tooling['packages']}, 'authenticated tooling receipt required')
    expected = dict(base)
    for row in tooling['packages']:
        require(row['name'] not in expected, 'extension may not replace base packages')
        expected[row['name']] = row['version']
    for row in c['baseline']:
        expected[row['name']] = row['version']
    actual = inventory(subprocess.check_output(['/usr/bin/pacman', '-Q'], text=True, timeout=30))
    require(actual == expected, 'installed package inventory differs from full base + tooling + four originals')
    for row in c['baseline']:
        names = subprocess.check_output(['/usr/bin/bsdtar', '-tf', '/inputs/' + row['archive']], text=True, timeout=15).splitlines()
        require(len(names) == len(set(names)) and
                {n for n in names if not n.endswith('/') and n not in ('.PKGINFO', '.BUILDINFO', '.MTREE', '.Changelog')} == set(row['payload_sha256']),
                'original archive payload map is incomplete or contains extra files')
        for name in names:
            relative(name.rstrip('/'))
        metadata = subprocess.check_output(['/usr/bin/bsdtar', '-xOf', '/inputs/' + row['archive'], '.PKGINFO'], text=True, timeout=15)
        require('pkgname = ' + row['name'] + '\n' in metadata and 'pkgver = ' + row['version'] + '\n' in metadata, 'original archive metadata differs')
        for name, value in row['payload_sha256'].items():
            path = Path('/') / name
            require(not path.is_symlink() and path.is_file() and digest(path) == value, 'installed original payload differs: ' + name)
            owner = subprocess.check_output(['/usr/bin/pacman', '-Qqo', str(path)], text=True, timeout=15).strip()
            require(owner == row['name'], 'original installed-file owner differs')
            data = subprocess.check_output(['/usr/bin/bsdtar', '-xOf', '/inputs/' + row['archive'], name], timeout=15)
            require(hashlib.sha256(data).hexdigest() == value, 'original archive payload differs')
    require(digest('/boot/Image') == IMAGE_SHA, 'signed generic kernel Image differs')
    return actual


def allocated(path):
    return sum(x.lstat().st_blocks * 512 for x in Path(path).rglob('*'))


def free_bytes(path):
    s = os.statvfs(path)
    return s.f_bavail * s.f_frsize


@contextmanager
def registered_spawn():
    """Defer cancellation until the child handle is registered; never mask it in children."""
    import signal
    import threading
    require(threading.current_thread() is threading.main_thread(), 'process spawning requires main thread')
    pending, previous = [], {}
    def remember(sig, frame):
        pending.append((sig, frame))
    try:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            handler = signal.getsignal(sig)
            if handler != signal.SIG_IGN:
                previous[sig] = signal.signal(sig, remember)
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        for sig, frame in pending:
            handler = previous[sig]
            if callable(handler):
                handler(sig, frame)
            else:
                # Raising permits the owner's finally to reap the child even when
                # the original disposition would terminate without Python cleanup.
                raise InterruptedError('cancelled during process registration: ' + str(sig))


def reap(process):
    import signal
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def bounded(argv, *, env=None, timeout=30, limit=1024 ** 2, log=None):
    """Stream a trusted process with a combined output cap and group cleanup."""
    import selectors
    import signal
    import time
    process = None
    streams = {'stdout': bytearray(), 'stderr': bytearray()}
    total, error = 0, None
    start = time.monotonic()
    output = Path(log).open('xb') if log else None
    try:
        with registered_spawn():
            process = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for name in streams:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                if time.monotonic() - start >= timeout:
                    error = 'timeout'
                    break
                for key, _ in selector.select(.05):
                    data = os.read(key.fd, min(65536, limit - total + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    take = min(len(data), limit - total)
                    streams[key.data].extend(data[:take])
                    if output:
                        output.write(data[:take])
                    total += take
                    if take < len(data):
                        error = 'output overflow'
                        break
                if error:
                    break
        if not error:
            process.wait(timeout=max(.1, timeout - (time.monotonic() - start)))
    finally:
        with registered_spawn():
            try:
                if process:
                    reap(process)
                    process.stdout.close()
                    process.stderr.close()
            finally:
                if output:
                    output.close()
    return {'returncode': process.returncode, 'error': error,
            **{name: data.decode(errors='replace') for name, data in streams.items()}}


class LoggedProcess:
    """Immediately drain/cap a long-lived session's merged output to one log."""
    def __init__(self, argv, path, *, env=None, limit=1024 ** 2, stdin=None):
        import signal
        import threading
        self.error = None
        self.limit = limit
        self.process = self.thread = None
        output = Path(path).open('xb')
        def drain():
            written = 0
            try:
                with output as stream:
                    while data := self.process.stdout.read1(min(16384, limit - written + 1)):
                        take = min(len(data), limit - written)
                        stream.write(data[:take])
                        stream.flush()
                        written += take
                        if take < len(data):
                            self.error = 'output overflow'
                            break
            except Exception as exc:
                self.error = str(exc)
            finally:
                if self.error:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.process.stdout.close()
        try:
            with registered_spawn():
                self.process = subprocess.Popen(argv, env=env, stdin=stdin, stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT, start_new_session=True)
                self.thread = threading.Thread(target=drain, daemon=True)
                self.thread.start()
        except BaseException:
            with registered_spawn():
                try:
                    if self.process is not None:
                        reap(self.process)
                    if self.thread is not None and self.thread.ident is not None:
                        self.thread.join(timeout=5)
                    if self.process is not None:
                        self.process.stdout.close()
                finally:
                    output.close()
            raise

    def finish(self):
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), 'log drain cleanup incomplete')
        require(self.error is None, 'session logging failed: ' + str(self.error))
