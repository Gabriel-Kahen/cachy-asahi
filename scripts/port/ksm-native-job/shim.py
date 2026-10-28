#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""PATH Docker shim: bounded Unix RPC only; never launches Docker itself."""
import base64
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

REQUEST_LIMIT = 65536
RESPONSE_LIMIT = 8 * 1024**2
CLIENT_TIMEOUT = 2600


def exchange(argv, environ=None):
    env = os.environ if environ is None else environ
    path, token = Path(env.get('KSM_DOCKER_BROKER_SOCKET', '')), env.get('KSM_DOCKER_BROKER_TOKEN', '')
    if not path.is_absolute() or '..' in path.parts or len(str(path).encode()) >= 104 or not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('bound private RPC endpoint required')
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            os.close(parent_fd); parent_fd = child
        parent = os.fstat(parent_fd)
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise ValueError('private socket ownership required')
    except BaseException:
        os.close(parent_fd)
        raise
    try:
        if type(argv) is not list or not argv or len(argv) > 127 or any(type(x) is not str or not x or '\0' in x or len(x) > 8192 for x in argv):
            raise ValueError('bounded argv required')
        data = json.dumps({'token': token, 'argv': argv}, separators=(',', ':')).encode()
        if len(data) > REQUEST_LIMIT: raise ValueError('request byte bound')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(CLIENT_TIMEOUT)
            connection.connect(f'/proc/self/fd/{parent_fd}/{path.name}')
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer[1] != os.geteuid(): raise ValueError('server owner drift')
            after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino): raise ValueError('socket identity drift')
            connection.sendall(struct.pack('!I', len(data)) + data)
            def exact(size):
                result = bytearray()
                while len(result) < size:
                    block = connection.recv(min(65536, size - len(result)))
                    if not block: raise ValueError('truncated RPC response')
                    result.extend(block)
                return bytes(result)
            size = struct.unpack('!I', exact(4))[0]
            if not 0 < size <= RESPONSE_LIMIT * 2: raise ValueError('response byte bound')
            response = json.loads(exact(size))
        if type(response) is not dict or set(response) != {'code', 'stdout'} or type(response['code']) is not int or not 0 <= response['code'] <= 255:
            raise ValueError('response schema')
        output = base64.b64decode(response['stdout'], validate=True)
        if len(output) > RESPONSE_LIMIT: raise ValueError('stdout byte bound')
        return response['code'], output
    finally:
        os.close(parent_fd)


def main(argv=None):
    try:
        code, output = exchange(sys.argv[1:] if argv is None else argv)
        sys.stdout.buffer.write(output); sys.stdout.buffer.flush()
        return code
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('scoped Docker shim refused: ' + type(error).__name__, file=sys.stderr)
        return 125


if __name__ == '__main__':
    raise SystemExit(main())
