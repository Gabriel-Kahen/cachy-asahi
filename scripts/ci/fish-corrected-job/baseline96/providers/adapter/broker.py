#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Pinned local Docker operations and nonce-owned container cleanup only."""
import hashlib
import http.client
import io
import json
import errno
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import sys
import time
import uuid
from runtime import Cancelled, Runner, defer_signals

LABEL = 'org.cachy-asahi.fdk-stage.nonce'
PROBE = 'id -u; id -g; LC_ALL=C pacman -Q | LC_ALL=C sort'
DESTINATIONS = {'/inputs': True, '/out': False, '/builder-entry.sh': True,
                '/expected-packages.lock': True}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def validate_endpoint(endpoint, uid):
    allowed = {'unix:///var/run/docker.sock', 'unix:///run/docker.sock',
               f'unix:///run/user/{uid}/docker.sock'}
    need(endpoint in allowed, 'docker-endpoint')
    canonical = Path(endpoint[7:]).resolve()
    need(str(canonical) in ('/run/docker.sock', f'/run/user/{uid}/docker.sock'), 'docker-endpoint')
    return 'unix://' + str(canonical)


def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'docker-regular-input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        need(len(data) <= limit, 'docker-input-size')
        return data, info
    finally:
        os.close(fd)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'docker-duplicate-json-key')
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique)


def strict_chunks(data):
    offset = 0
    while True:
        end = data.find(b'\r\n', offset, offset + 18)
        need(end >= 0 and re.fullmatch(rb'[0-9a-fA-F]{1,16}', data[offset:end]),
             'docker-daemon-chunk-framing')
        size = int(data[offset:end], 16)
        offset = end + 2
        if size == 0:
            need(data[offset:] == b'\r\n', 'docker-daemon-chunk-framing')
            return
        need(size <= 8 * 1024 * 1024 and offset + size + 2 <= len(data) and
             data[offset + size:offset + size + 2] == b'\r\n', 'docker-daemon-chunk-framing')
        offset += size + 2


def daemon_http(path, deadline):
    """Only GET /info; collect bounded wire bytes before offline HTTP decoding."""
    end = min(deadline, time.monotonic() + 15)
    need(end > time.monotonic(), 'docker-daemon-timeout')
    wire = bytearray()
    request = memoryview(b'GET /info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
                         b'Accept: application/json\r\nAccept-Encoding: identity\r\n\r\n')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection, selectors.DefaultSelector() as selector:
        connection.setblocking(False)
        code = connection.connect_ex(str(path))
        need(code in (0, errno.EINPROGRESS, errno.EAGAIN, errno.EWOULDBLOCK), 'docker-daemon-connect')
        selector.register(connection, selectors.EVENT_WRITE)
        sending = True
        while True:
            left = end - time.monotonic()
            need(left > 0, 'docker-daemon-timeout')
            if not selector.select(left):
                raise ValueError('docker-daemon-timeout')
            need(connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, 'docker-daemon-connect')
            try:
                if sending:
                    count = connection.send(request)
                    need(count > 0, 'docker-daemon-send')
                    request = request[count:]
                    if not request:
                        sending = False
                        selector.modify(connection, selectors.EVENT_READ)
                else:
                    data = connection.recv(65536)
                    if not data:
                        break
                    need(len(wire) + len(data) <= 8 * 1024 * 1024, 'docker-daemon-output-bound')
                    wire.extend(data)
            except BlockingIOError:
                continue
    class Buffer(io.BytesIO):
        def close(self):
            self.position = self.tell()
            super().close()
    stream = Buffer(wire)
    class OfflineSocket:
        def makefile(self, mode):
            return stream
    response = http.client.HTTPResponse(OfflineSocket())
    try:
        response.begin()
        need(response.status == 200, 'docker-daemon-http-status')
        lengths = response.headers.get_all('Content-Length', [])
        transfers = response.headers.get_all('Transfer-Encoding', [])
        encoding = response.headers.get_all('Content-Encoding', [])
        need(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers) and
             transfers in ([], ['chunked']) and encoding in ([], ['identity']), 'docker-daemon-http-framing')
        if lengths:
            need(re.fullmatch('[0-9]{1,8}', lengths[0]) and int(lengths[0]) <= 8 * 1024 * 1024,
                 'docker-daemon-http-framing')
        if transfers:
            strict_chunks(wire[stream.tell():])
        body = response.read(8 * 1024 * 1024 + 1)
        need(len(body) <= 8 * 1024 * 1024, 'docker-daemon-output-bound')
        need(not lengths or len(body) == int(lengths[0]), 'docker-daemon-http-truncated')
        position = stream.position if stream.closed else stream.tell()
        need(position == len(wire), 'docker-daemon-http-trailing')
        data = decode(body)
        need(time.monotonic() < end, 'docker-daemon-timeout')
        return data
    except (http.client.HTTPException, UnicodeError) as error:
        raise ValueError('docker-daemon-http-invalid') from error
    finally:
        response.close()


class Broker:
    def __init__(self, runner, cleanup_runner, binary, binary_sha, endpoint, image,
                 uid, gid, journal_path, nonce, *, expected_mounts=None):
        need(type(uid) is int and type(gid) is int and 0 < uid < 2**31 and 0 < gid < 2**31,
             'docker-ordinary-user')
        need(type(binary_sha) is str and re.fullmatch('[0-9a-f]{64}', binary_sha), 'docker-binary-pin')
        need(type(image) is str and re.fullmatch('sha256:[0-9a-f]{64}', image), 'docker-image-pin')
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{16,64}', nonce), 'docker-nonce')
        self.runner, self.cleanup_runner = runner, cleanup_runner
        self.binary, self.binary_sha = Path(binary), binary_sha
        need(self.binary.is_absolute() and self.binary == self.binary.resolve(), 'docker-binary-path')
        self.endpoint = validate_endpoint(endpoint, uid)
        self.socket = Path(self.endpoint[7:])
        self.image, self.uid, self.gid, self.nonce = image, uid, gid, nonce
        self.journal_path = Path(journal_path)
        need(self.journal_path.is_absolute() and self.journal_path.parent == self.journal_path.parent.resolve(),
             'docker-journal-path')
        self.expected_mounts = expected_mounts
        self.daemon, self.pins, self.image_config = None, None, None
        self.last_cleanup = {'status': 'NOT RUN', 'absence_verified': False}

    def _local(self, runner):
        need(set(runner.env) <= {'PATH', 'LANG', 'LC_ALL', 'HOME', 'DOCKER_CONFIG'} and
             {'PATH', 'HOME', 'DOCKER_CONFIG'} <= set(runner.env), 'docker-environment')
        config = Path(runner.env['DOCKER_CONFIG'])
        need(config.is_absolute() and config == config.resolve() and config.is_dir() and
             not config.is_symlink() and config.stat().st_uid == os.getuid() and
             config.stat().st_mode & 0o077 == 0 and not list(config.iterdir()) and
             not self.binary.is_relative_to(config), 'docker-config')
        home = Path(runner.env['HOME'])
        need(home.is_absolute() and home == home.resolve() and home.is_dir() and
             home.stat().st_uid == os.getuid() and home.stat().st_mode & 0o077 == 0, 'docker-home')
        data, info = regular(self.binary, 64 * 1024 * 1024)
        need(hashlib.sha256(data).hexdigest() == self.binary_sha and info.st_mode & 0o111,
             'docker-binary-drift')
        socket = self.socket.lstat()
        need(stat.S_ISSOCK(socket.st_mode) and self.socket == self.socket.resolve(), 'docker-socket')
        current = {'binary': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode],
                   'socket': [socket.st_dev, socket.st_ino, socket.st_uid, socket.st_gid, socket.st_mode]}
        if self.pins is not None:
            need(current == self.pins, 'docker-local-pin-drift')
        return current

    def _raw(self, args, runner, timeout=30):
        self._local(runner)
        result = runner.run([str(self.binary), '--host', self.endpoint, *args], timeout=timeout,
                            log='docker-' + uuid.uuid4().hex + '.log')
        self._local(runner)
        return result

    def _info(self, runner):
        end = min(runner.deadline, time.monotonic() + 15)
        self._local(runner)
        data = daemon_http(self.socket, end)
        self._local(runner)
        need(time.monotonic() < end, 'docker-daemon-timeout')
        identity = {'id': data['ID'], 'architecture': data['Architecture']}
        need(type(identity['id']) is str and re.fullmatch('[A-Za-z0-9:_-]{8,128}', identity['id']) and
             identity['architecture'] in ('aarch64', 'arm64') and data.get('OSType') == 'linux',
             'docker-native-daemon')
        if self.daemon is not None:
            need(identity == self.daemon, 'docker-daemon-drift')
        return identity

    def _operation(self, args, *, cleanup=False, timeout=30):
        need(self.daemon is not None, 'docker-uninitialized')
        runner = self.cleanup_runner if cleanup else self.runner
        self._info(runner)
        result = self._raw(args, runner, timeout)
        self._info(runner)
        return result

    def _identity(self):
        return {'nonce': self.nonce, 'image': self.image, 'uid': self.uid, 'gid': self.gid,
                'endpoint': self.endpoint, 'binary_sha256': self.binary_sha,
                'daemon': self.daemon, 'local_pins': self.pins}

    def _journal(self):
        data, _ = regular(self.journal_path, 65536)
        record = decode(data)
        need(type(record) is dict and set(record) == {'schema_version', 'identity', 'containers'} and
             record['schema_version'] == 1 and record['identity'] == self._identity() and
             type(record['containers']) is list and len(record['containers']) <= 16, 'docker-journal-binding')
        names = set()
        for row in record['containers']:
            need(type(row) is dict and set(row) == {'name', 'id', 'mounts', 'env', 'cmd', 'create_attempted'} and
                 re.fullmatch('cachy-asahi-[a-z0-9-]{8,96}', row['name']) and row['name'] not in names and
                 (row['id'] is None or re.fullmatch('[0-9a-f]{64}', row['id'])) and
                 type(row['mounts']) is dict and type(row['env']) is dict and type(row['cmd']) is list and
                 type(row['create_attempted']) is bool,
                 'docker-journal-container')
            names.add(row['name'])
        return record

    def _write(self, record, first=False):
        data = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
        need(len(data) <= 65536, 'docker-journal-size')
        path = self.journal_path if first else self.journal_path.with_name('.journal-' + uuid.uuid4().hex)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if not first:
                os.replace(path, self.journal_path)
            directory = os.open(self.journal_path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if not first:
                path.unlink(missing_ok=True)

    def initialize(self, expected_daemon=None):
        self.pins = self._local(self.runner)
        self._local(self.cleanup_runner)
        self.daemon = self._info(self.runner)
        if expected_daemon is not None:
            need(self.daemon == expected_daemon, 'docker-expected-daemon')
        result = self._operation(['image', 'inspect', self.image])
        need(result.returncode == 0, 'docker-image-query')
        rows = decode(result.stdout)
        need(type(rows) is list and len(rows) == 1 and rows[0]['Id'] == self.image and
             rows[0]['Architecture'] == 'arm64' and rows[0]['Os'] == 'linux', 'docker-image-binding')
        self.image_config = rows[0].get('Config', {})
        need(type(self.image_config) is dict and not self.image_config.get('Volumes'),
             'docker-image-volumes')
        if self.journal_path.exists() or self.journal_path.is_symlink():
            self._journal()
        else:
            self._write({'schema_version': 1, 'identity': self._identity(), 'containers': []}, first=True)
        return dict(self.daemon)

    def capture(self, args):
        args = list(args)
        if args and args[0] in ('docker', str(self.binary)):
            args = args[1:]
        need(args in (['image', 'inspect', self.image], ['info', '--format', '{{.Architecture}}']),
             'docker-capture-command')
        if args[0] == 'info':
            return self._info(self.runner)['architecture']
        result = self._operation(args)
        need(result.returncode == 0, 'docker-image-query')
        rows = decode(result.stdout)
        need(len(rows) == 1 and rows[0]['Id'] == self.image and rows[0]['Architecture'] == 'arm64' and
             rows[0]['Os'] == 'linux' and rows[0].get('Config', {}) == self.image_config, 'docker-image-drift')
        return result.stdout.decode().strip()

    def _options(self, name, env, mounts):
        args = ['--name', name, '--pull=never', '--platform=linux/arm64', '--user', f'{self.uid}:{self.gid}',
                '--label', LABEL + '=' + self.nonce, '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--pids-limit=512', '--memory=4g', '--memory-swap=4g', '--cpus=4',
                '--network=none', '--ipc=private', '--cgroupns=private',
                '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--entrypoint', '/bin/bash']
        for key, value in sorted(env.items()):
            args += ['--env', key + '=' + value]
        for destination, source in sorted(mounts.items()):
            args += ['--mount', 'type=bind,src=' + source + ',dst=' + destination +
                     (',readonly' if DESTINATIONS[destination] else '')]
        return args

    def _build_request(self, command):
        need(type(command) is list and command[:2] == ['docker', 'run'] and
             all(type(arg) is str for arg in command), 'docker-build-command')
        flags, env, mounts, index = {}, {}, {}, 2
        switches = {'--rm', '--read-only'}
        values = {'--name', '--pull', '--platform', '--user', '--cap-drop', '--security-opt',
                  '--pids-limit', '--memory', '--cpus', '--network', '--tmpfs', '--env', '--mount', '--entrypoint'}
        while index < len(command) and command[index].startswith('--'):
            option, separator, value = command[index].partition('=')
            index += 1
            if option in switches:
                need(not separator and option not in flags, 'docker-build-options')
                flags[option] = True
                continue
            need(option in values, 'docker-build-options')
            if not separator:
                need(index < len(command), 'docker-build-options')
                value = command[index]
                index += 1
            if option == '--env':
                key, equal, item = value.partition('=')
                need(equal and key not in env, 'docker-build-env')
                env[key] = item
            elif option == '--mount':
                parts = value.split(',')
                row = {key: item for key, equal, item in (part.partition('=') for part in parts) if equal}
                readonly = 'readonly' in parts
                need(len(parts) == 3 + readonly and set(row) == {'type', 'src', 'dst'} and
                     row['type'] == 'bind' and row['dst'] in DESTINATIONS and row['dst'] not in mounts and
                     readonly == DESTINATIONS[row['dst']], 'docker-build-mounts')
                mounts[row['dst']] = row['src']
            else:
                need(option not in flags, 'docker-build-options')
                flags[option] = value
        name = flags.pop('--name', None)
        expected = {'--rm': True, '--pull': 'never', '--platform': 'linux/arm64',
                    '--user': f'{self.uid}:{self.gid}', '--cap-drop': 'ALL',
                    '--security-opt': 'no-new-privileges', '--read-only': True,
                    '--pids-limit': '512', '--memory': '4g', '--cpus': '4', '--network': 'none',
                    '--tmpfs': '/tmp:rw,nosuid,nodev,exec,size=4g', '--entrypoint': '/bin/bash'}
        need(flags == expected and type(name) is str and
             re.fullmatch('cachy-asahi-[0-9a-f]{16}', name) and
             command[index:] == [self.image, '/builder-entry.sh'], 'docker-build-policy')
        need(set(env) == {'CACHY_ASAHI_CONTAINER', 'SOURCE_DATE_EPOCH'} and
             env['CACHY_ASAHI_CONTAINER'] == '1' and env['SOURCE_DATE_EPOCH'] == '1791748800',
             'docker-build-env')
        need(type(self.expected_mounts) is dict and set(mounts) == set(DESTINATIONS) and
             mounts == {key: str(value) for key, value in self.expected_mounts.items()}, 'docker-build-mounts')
        for destination, value in mounts.items():
            path = Path(value)
            need(path.is_absolute() and path == path.resolve() and
                 not any(item.is_symlink() for item in (path, *path.parents)) and
                 (path.is_dir() if destination in ('/inputs', '/out') else path.is_file()), 'docker-mount-path')
        return name, env, mounts, ['/builder-entry.sh']

    def _inspect(self, identifier, row, cleanup=False):
        result = self._operation(['container', 'inspect', identifier], cleanup=cleanup)
        need(result.returncode == 0, 'docker-owned-inspect')
        records = decode(result.stdout)
        need(type(records) is list and len(records) == 1, 'docker-owned-inspect')
        item = records[0]
        config, host = item['Config'], item['HostConfig']
        need(re.fullmatch('[0-9a-f]{64}', item['Id']) and item['Name'] == '/' + row['name'] and
             (row['id'] is None or item['Id'] == row['id']) and item['Image'] == self.image and
             config['User'] == f'{self.uid}:{self.gid}' and config['Labels'].get(LABEL) == self.nonce,
             'docker-container-ownership')
        required = {'AutoRemove': False, 'Privileged': False, 'ReadonlyRootfs': True,
                    'NetworkMode': 'none', 'IpcMode': 'private', 'PidMode': '', 'CgroupnsMode': 'private',
                    'Memory': 4 * 1024**3, 'MemorySwap': 4 * 1024**3,
                    'NanoCpus': 4 * 10**9, 'PidsLimit': 512, 'CapDrop': ['ALL'],
                    'SecurityOpt': ['no-new-privileges'], 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,exec,size=4g'}}
        need(all(host.get(key) == value for key, value in required.items()) and
             not any(host.get(key) for key in ('CapAdd', 'Devices', 'DeviceRequests', 'Binds',
                                             'VolumesFrom', 'Links', 'PortBindings', 'GroupAdd')),
             'docker-container-resources')
        actual = {mount['Destination']: (mount['Source'], mount['RW']) for mount in item['Mounts']
                  if mount['Type'] == 'bind'}
        need(len(actual) == len(row['mounts']) and actual == {key: (value, not DESTINATIONS[key])
             for key, value in row['mounts'].items()} and
             all(mount['Type'] in ('bind', 'tmpfs') for mount in item['Mounts']), 'docker-container-mounts')
        expected_env = dict(entry.split('=', 1) for entry in self.image_config.get('Env', []))
        expected_env.update(row['env'])
        actual_env = config['Env'] or []
        need(len({entry.split('=', 1)[0] for entry in actual_env}) == len(actual_env) and
             dict(entry.split('=', 1) for entry in actual_env) == expected_env and
             config['Entrypoint'] == ['/bin/bash'] and config['Cmd'] == row['cmd'], 'docker-container-command')
        return item['Id']

    def _find(self, row, cleanup=False):
        filters = ['name=^/' + row['name'] + '$']
        if row['id'] is not None:
            filters.insert(0, 'id=' + row['id'])
        found = set()
        for value in filters:
            result = self._operation(['container', 'ls', '--all', '--no-trunc', '--format', '{{json .}}',
                                     '--filter', value], cleanup=cleanup)
            need(result.returncode == 0, 'docker-owned-list')
            rows = [decode(line) for line in result.stdout.splitlines() if line]
            need(len(rows) <= 1 and all(item['Names'] == row['name'] and
                 re.fullmatch('[0-9a-f]{64}', item['ID']) and
                 (row['id'] is None or item['ID'] == row['id']) for item in rows), 'docker-owned-list')
            found.update(item['ID'] for item in rows)
        need(len(found) <= 1, 'docker-owned-list')
        return next(iter(found)) if found else None

    def _launch(self, name, env, mounts, cmd, timeout):
        record = self._journal()
        need(len(record['containers']) < 16 and name not in {row['name'] for row in record['containers']},
             'docker-name-reservation')
        row = {'name': name, 'id': None, 'mounts': mounts, 'env': env, 'cmd': cmd, 'create_attempted': False}
        record['containers'].append(row)
        self._write(record)  # Durable reservation precedes create, including unknown outcomes.
        try:
            need(self._find(row) is None, 'docker-reserved-name-exists')
            row['create_attempted'] = True
            self._write(record)
            result = self._operation(['create', *self._options(name, env, mounts), self.image, *cmd],
                                     timeout=min(timeout, 30))
            if result.returncode:
                return result
            identifier = result.stdout.decode().strip()
            need(re.fullmatch('[0-9a-f]{64}', identifier), 'docker-create-unknown')
            row['id'] = identifier
            self._write(record)
            self._inspect(identifier, row)
            return self._operation(['start', '--attach', row['id']], timeout=timeout)
        finally:
            failed = sys.exc_info()[0] is not None
            with defer_signals() as events:
                self.last_cleanup = self.cleanup()
            if events:
                raise Cancelled(events[0])
            if self.last_cleanup.get('cancelled'):
                raise Cancelled()
            if not failed:
                need(self.last_cleanup['status'] == 'PASS', 'docker-cleanup-failed')

    def build(self, command, timeout):
        need(type(timeout) in (int, float) and 0 < timeout <= 10800, 'docker-build-timeout')
        name, env, mounts, cmd = self._build_request(command)
        return self._launch(name, env, mounts, cmd, timeout)

    def probe(self):
        result = self._launch('cachy-asahi-probe-' + self.nonce, {}, {}, ['-euc', PROBE], 60)
        need(result.returncode == 0, 'docker-probe-failed')
        lines = result.stdout.splitlines(keepends=True)
        need(len(lines) > 2 and lines[:2] == [f'{self.uid}\n'.encode(), f'{self.gid}\n'.encode()] and
             lines[2:] == sorted(lines[2:]) and all(re.fullmatch(rb'[a-zA-Z0-9@+_.-]+ [^\s]+\n', line)
             for line in lines[2:]) and len({line.split()[0] for line in lines[2:]}) == len(lines[2:]),
             'docker-probe-identity-inventory')
        return result.stdout

    def cleanup(self):
        errors, cancelled = [], False
        with defer_signals() as events:
            try:
                self.cleanup_runner = Runner(60, self.cleanup_runner.env, self.cleanup_runner.log_dir)
                record = self._journal()  # Reload names reserved by a killed worker.
                for row in record['containers']:
                    for attempt in range(2):
                        try:
                            identifier = self._find(row, cleanup=True)
                            need(identifier is not None or row['id'] is not None or not row['create_attempted'],
                                 'docker-create-absence-uncertain')
                            if identifier is not None:
                                self._inspect(identifier, row, cleanup=True)
                                row['id'] = identifier
                                self._write(record)
                                result = self._operation(['container', 'rm', '--force', identifier], cleanup=True)
                                need(result.returncode == 0, 'docker-owned-remove')
                            need(self._find(row, cleanup=True) is None, 'docker-owned-absence')
                            break
                        except Cancelled:
                            cancelled = True
                            if attempt == 1:
                                errors.append('docker-cleanup-cancellation-uncertain')
                        except (OSError, ValueError, KeyError, TypeError) as error:
                            errors.append(str(error))
                            break
            except Cancelled:
                cancelled = True
                errors.append('docker-cleanup-cancellation-uncertain')
            except (OSError, ValueError, KeyError, TypeError) as error:
                errors.append(str(error))
        cancelled = cancelled or bool(events)
        return {'status': 'FAIL' if errors or cancelled else 'PASS', 'absence_verified': not errors,
                'cancelled': cancelled, 'errors': errors}
