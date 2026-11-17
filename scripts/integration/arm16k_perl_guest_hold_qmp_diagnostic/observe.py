# SPDX-License-Identifier: MIT
"""Proposal-only metadata observer. Borrowed sockets/pidfd are never consumed."""
import fcntl
import json
import os
import re
import select
import socket
import stat
import struct
import time

STAGES = ('HOLD', 'BEFORE_QUIT', 'DEADLINE')
CPU = ('usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled',
       'throttled_usec', 'nr_bursts', 'burst_usec')
MEMORY = ('low', 'high', 'max', 'oom', 'oom_kill', 'oom_group_kill')
STATES = frozenset('RSDZTtXxKWPI')
MAX_THREADS, READ_CAP, SERIAL_CAP = 32, 4096, 1048576
SAMPLE_SECONDS, SAMPLE_CAP, JOURNAL_CAP = .05, 16384, 65536
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
ERROR_CODES = frozenset(('METADATA_DEADLINE', 'METADATA_TYPE', 'METADATA_BYTES',
    'COUNTER_FORMAT', 'PROCESS_FORMAT', 'PROCESS_IDENTITY', 'PROCESS_STATE',
    'CGROUP_FORMAT', 'CGROUP_IDENTITY', 'SOCKET_COUNTER', 'SOCKET_IDENTITY',
    'BORROWED_FD_IDENTITY', 'PIDFD_IDENTITY', 'PIDFD_READY', 'THREAD_FORMAT',
    'SERIAL_BUFFER_BOUND'))


class ObservationError(ValueError):
    pass


def _need(value, code):
    if not value:
        raise ObservationError(code)


def _tick(end):
    _need(time.monotonic() < end, 'METADATA_DEADLINE')


def _fd_identity(fd):
    value = os.fstat(fd)
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _read(path, end, *, directory=None):
    _tick(end)
    fd = os.open(path, FLAGS, dir_fd=directory)
    try:
        _need(stat.S_ISREG(os.fstat(fd).st_mode), 'METADATA_TYPE')
        value = os.read(fd, READ_CAP + 1)
        _need(len(value) <= READ_CAP, 'METADATA_BYTES')
    finally:
        os.close(fd)
    _tick(end)
    return value


def _proc(pid, suffix, end):
    return _read('/proc/' + str(pid) + '/' + suffix, end)


def _number(value):
    _need(type(value) is bytes and re.fullmatch(rb'[0-9]{1,20}', value), 'COUNTER_FORMAT')
    result = int(value)
    _need(result <= 2**64 - 1, 'COUNTER_FORMAT')
    return result


def _process(pid, suffix, end):
    raw = _proc(pid, suffix, end)
    head, sep, tail = raw.rpartition(b')')
    fields = tail.split()
    _need(sep and b'(' in head and len(fields) >= 20, 'PROCESS_FORMAT')
    actual = _number(head.split(b'(', 1)[0].strip())
    _need(actual == int(suffix.split('/')[-2]) if '/' in suffix else actual == pid,
          'PROCESS_IDENTITY')
    state = fields[0].decode('ascii')
    _need(state in STATES, 'PROCESS_STATE')
    return dict(pid=actual, start_ticks=_number(fields[19]), parent=_number(fields[1]),
                group=_number(fields[2]), session=_number(fields[3]), state=state,
                user_ticks=_number(fields[11]), system_ticks=_number(fields[12]),
                num_threads=_number(fields[17]))


def _process_identity(value):
    return tuple(value[k] for k in ('pid', 'start_ticks', 'parent', 'group', 'session'))


def _group_parts(pid, end):
    rows = _proc(pid, 'cgroup', end).splitlines()
    _need(len(rows) == 1 and rows[0].startswith(b'0::/'), 'CGROUP_FORMAT')
    path = rows[0][3:]
    _need(len(path) <= 1024, 'CGROUP_FORMAT')
    parts = path.split(b'/')[1:]
    if parts == [b'']:
        return ()
    _need(len(parts) <= 16 and all(0 < len(p) <= 255 and p not in (b'.', b'..')
          and re.fullmatch(rb'[A-Za-z0-9_.@:-]+', p) for p in parts), 'CGROUP_FORMAT')
    return tuple(p.decode('ascii') for p in parts)


def _open_group(parts, end):
    _tick(end)
    fd = os.open('/sys/fs/cgroup', FLAGS | os.O_DIRECTORY)
    try:
        for part in parts:
            _tick(end)
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        _tick(end)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _counters(body, names):
    rows = {}
    for line in body.splitlines():
        pair = line.split()
        _need(len(pair) == 2 and pair[0] not in rows, 'COUNTER_FORMAT')
        rows[pair[0]] = _number(pair[1])
    return {key: rows.get(key.encode()) for key in names}


def _socket_values(stream, end):
    _tick(end)
    readable, writable, exceptional = select.select([stream], [stream], [stream], 0)
    value = dict(readable=bool(readable), writable=bool(writable), exceptional=bool(exceptional))
    for key, operation in (
            ('input_queued_bytes', lambda: struct.unpack('i', fcntl.ioctl(stream, 0x541B, struct.pack('i', 0)))[0]),
            ('output_kernel_accounted_bytes', lambda: struct.unpack('i', fcntl.ioctl(stream, 0x5411, struct.pack('i', 0)))[0]),
            ('receive_buffer_bytes', lambda: stream.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)),
            ('send_buffer_bytes', lambda: stream.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))):
        _tick(end)
        value[key] = operation()
        _tick(end)
    _need(all(type(v) is bool or type(v) is int and 0 <= v <= 2**31-1
              for v in value.values()), 'SOCKET_COUNTER')
    return value


class Binding:
    """Bind just after original Serial construction, under the existing case guard.

    sample() is diagnostic DATA only: never acceptance, liveness authority, a
    replacement for peer.check(), a reader, or a retirement/cleanup primitive.
    """
    def __init__(self, peer=None, serial=None):
        _need(peer is not None and serial is not None, 'UNBOUND_OR_UNISSUED')
        self.peer, self.serial = peer, serial
        self.qmp, self.ssocket = peer.stream, serial.stream
        self.pid, self.start = peer.qemu['pid'], peer.qemu['start']
        _need(type(self.pid) is int and self.pid > 1 and type(self.start) is int
              and self.start > 0 and peer.credentials[0] == self.pid, 'PROCESS_IDENTITY')
        _need(type(peer.fds) is list and peer.fds, 'PIDFD_IDENTITY')
        self.pidfd = peer.fds[0]
        self.qfd, self.sfd = self.qmp.fileno(), self.ssocket.fileno()
        _need(self.qfd == peer.fd and len({self.qfd, self.sfd, self.pidfd}) == 3,
              'BORROWED_FD_IDENTITY')
        self.creds = tuple(peer.credentials)
        end = time.monotonic() + SAMPLE_SECONDS
        _tick(end)
        self.identities = {fd: _fd_identity(fd) for fd in (self.qfd, self.sfd, self.pidfd)}
        _need(all(self.identities[fd][2] == stat.S_IFSOCK for fd in (self.qfd, self.sfd)),
              'SOCKET_IDENTITY')
        self.next_stage, self.bytes_retained = 0, 0
        self._borrowed(end)
        process = _process(self.pid, 'stat', end)
        _need(process['start_ticks'] == self.start and process['parent'] == peer.actor_pid,
              'PROCESS_IDENTITY')
        self.process_identity = _process_identity(process)
        self.group_parts = _group_parts(self.pid, end)
        fd = _open_group(self.group_parts, end)
        try:
            self.group_identity = _fd_identity(fd)
        finally:
            os.close(fd)
        self._borrowed(end)
        _need(_process_identity(_process(self.pid, 'stat', end)) == self.process_identity,
              'PROCESS_IDENTITY')

    def _borrowed(self, end):
        _tick(end)
        _need(self.peer.stream is self.qmp and self.serial.stream is self.ssocket
              and self.qmp.fileno() == self.qfd == self.peer.fd
              and self.ssocket.fileno() == self.sfd and self.peer.fds
              and self.peer.fds[0] == self.pidfd, 'BORROWED_FD_IDENTITY')
        _need(all(_fd_identity(fd) == value for fd, value in self.identities.items()),
              'BORROWED_FD_IDENTITY')
        for stream in (self.qmp, self.ssocket):
            _need(struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                  == self.creds, 'SOCKET_IDENTITY')
        poll = select.poll()
        poll.register(self.pidfd, select.POLLIN | select.POLLERR | select.POLLHUP)
        _need(not poll.poll(0), 'PIDFD_READY')
        info = _read('/proc/self/fdinfo/' + str(self.pidfd), end)
        rows = [line.split() for line in info.splitlines() if line.startswith(b'Pid:')]
        _need(len(rows) == 1 and len(rows[0]) == 2 and _number(rows[0][1]) == self.pid,
              'PIDFD_IDENTITY')
        _tick(end)

    def _threads(self, end, errors):
        tids, limited = [], False
        with os.scandir('/proc/' + str(self.pid) + '/task') as entries:
            for entry in entries:
                _tick(end)
                _need(re.fullmatch('[1-9][0-9]{0,9}', entry.name), 'THREAD_FORMAT')
                if len(tids) == MAX_THREADS:
                    limited = True
                    errors.append('THREAD_BOUND')
                    break
                tids.append(int(entry.name))
        rows = []
        for tid in sorted(tids):
            try:
                value = _process(self.pid, 'task/' + str(tid) + '/stat', end)
                rows.append(dict(tid=tid, start_ticks=value['start_ticks'], state=value['state'],
                                 user_ticks=value['user_ticks'], system_ticks=value['system_ticks']))
            except (OSError, ObservationError):
                _tick(end)
                errors.append('THREAD_UNAVAILABLE')
        return dict(limited=limited, sampled=len(rows), rows=rows)

    def _cgroup(self, end, errors):
        _need(_group_parts(self.pid, end) == self.group_parts, 'CGROUP_IDENTITY')
        fd = _open_group(self.group_parts, end)
        try:
            _need(_fd_identity(fd) == self.group_identity, 'CGROUP_IDENTITY')
            result = dict(identity=dict(device=self.group_identity[0], inode=self.group_identity[1]),
                          cpu_stat={k: None for k in CPU}, memory_current_bytes=None,
                          memory_events={k: None for k in MEMORY},
                          memory_events_local={k: None for k in MEMORY})
            for name, key, names in (('cpu.stat', 'cpu_stat', CPU),
                                     ('memory.events', 'memory_events', MEMORY),
                                     ('memory.events.local', 'memory_events_local', MEMORY),
                                     ('memory.current', 'memory_current_bytes', None)):
                try:
                    raw = _read(name, end, directory=fd)
                    result[key] = _counters(raw, names) if names else _number(raw.strip())
                    if names and any(v is None for v in result[key].values()):
                        errors.append('COUNTER_FIELD_UNAVAILABLE')
                except (OSError, ObservationError):
                    _tick(end)
                    errors.append('COUNTER_UNAVAILABLE')
            _need(_fd_identity(fd) == self.group_identity, 'CGROUP_IDENTITY')
            return result
        finally:
            os.close(fd)

    def sample(self, stage):
        _need(self.next_stage < len(STAGES) and stage == STAGES[self.next_stage], 'STAGE_ORDER')
        self.next_stage += 1  # A failed observation is not retried.
        began = time.monotonic()
        end = began + SAMPLE_SECONDS
        result = dict(schema=1, stage=stage, status='UNAVAILABLE', elapsed_ns=0, pidfd_live=None,
                      process=None, threads=None, cgroup=None, qmp=None, serial=None,
                      serial_buffer=None, errors=[], VM_acceptance=None, Root_acceptance=None)
        try:
            self._borrowed(end)
            result['pidfd_live'] = True
            process = _process(self.pid, 'stat', end)
            _need(_process_identity(process) == self.process_identity, 'PROCESS_IDENTITY')
            result['process'] = process
            result['threads'] = self._threads(end, result['errors'])
            result['cgroup'] = self._cgroup(end, result['errors'])
            _tick(end)
            result['qmp'], result['serial'] = _socket_values(self.qmp, end), _socket_values(self.ssocket, end)
            size, offset = len(self.serial.data), self.serial.offset
            _need(type(offset) is int and 0 <= offset <= size <= SERIAL_CAP, 'SERIAL_BUFFER_BOUND')
            result['serial_buffer'] = dict(bytes_retained=size, offset=offset, read_ahead_bytes=size-offset)
            self._borrowed(end)
            _need(_process_identity(_process(self.pid, 'stat', end)) == self.process_identity,
                  'PROCESS_IDENTITY')
            _need(_group_parts(self.pid, end) == self.group_parts, 'CGROUP_IDENTITY')
            result['status'] = 'PARTIAL_METADATA_ONLY' if result['errors'] else 'PUBLIC_METADATA_ONLY'
        except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
            code = 'METADATA_UNAVAILABLE'
            if isinstance(exc, ObservationError) and exc.args and exc.args[0] in ERROR_CODES:
                code = exc.args[0]
            result.update(status='DEADLINE' if code == 'METADATA_DEADLINE' else
                          'IDENTITY_LOST' if code.endswith('IDENTITY') or code == 'PIDFD_READY' else 'UNAVAILABLE',
                          pidfd_live=False if code == 'PIDFD_READY' else None,
                          process=None, threads=None, cgroup=None, qmp=None,
                          serial=None, serial_buffer=None, errors=[code])
        result['elapsed_ns'] = max(0, int((time.monotonic()-began)*1e9))
        result['errors'] = list(dict.fromkeys(result['errors']))
        body = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
        if len(body) > SAMPLE_CAP or self.bytes_retained + len(body) > JOURNAL_CAP:
            result.update(status='UNAVAILABLE', process=None, threads=None, cgroup=None, qmp=None,
                          serial=None, serial_buffer=None, errors=['OUTPUT_BOUND'])
            body = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
        self.bytes_retained += len(body)
        return result


if __name__ == '__main__':
    raise SystemExit('Proposal only; no operational entry. Compose only under a separately issued case.')
