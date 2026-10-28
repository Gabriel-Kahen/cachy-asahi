#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One nonce-owned derived image, committed with the accepted base config."""
import http.client
import errno
import io
import json
import os
from pathlib import Path
import re
import socket
import selectors
import stat
import time
from urllib.parse import quote, urlencode

from common import module, need, save, unique
from evidence import Trace, observed, scope

API_VERSION = '1.48'
INVENTORY_LIMIT = 128 * 1024
MAX_IMAGES = 256
IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
FIELDS = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes', 'ExposedPorts',
          'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped')


def effective(config):
    value = {key: config.get(key) for key in FIELDS}
    labels = value['Labels']
    need(labels is None or type(labels) is dict and
         all(type(key) is str and type(item) is str for key, item in labels.items()),
         'derived image config/identity differs')
    value['Labels'] = {} if labels is None else dict(labels)
    if value['Entrypoint'] in (None, [], ['']): value['Entrypoint'] = None
    if value['Cmd'] in (None, []): value['Cmd'] = None
    return value


def wire(path, method, target, body, deadline, observer=None):
    """Bounded aggregate connect/write/read time, not an idle socket timeout."""
    body = b'' if body is None else body
    need(len(body) <= 65536 and method in ('GET', 'POST') and '\r' not in target and '\n' not in target, 'bounded API request required')
    request = memoryview((method + ' ' + target + ' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
        'Accept: application/json\r\nAccept-Encoding: identity\r\nContent-Type: application/json\r\nContent-Length: ' +
        str(len(body)) + '\r\n\r\n').encode() + body)
    received = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel, selectors.DefaultSelector() as selector:
        channel.setblocking(False)
        need(channel.connect_ex(path) in (0, errno.EINPROGRESS, errno.EAGAIN, errno.EWOULDBLOCK), 'API connect failed')
        selector.register(channel, selectors.EVENT_WRITE)
        sending = True
        while True:
            remaining = deadline - time.monotonic()
            need(remaining > 0 and selector.select(remaining), 'API aggregate timeout')
            need(channel.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0, 'API socket failed')
            try:
                if sending:
                    sent = channel.send(request); need(sent > 0, 'API send failed'); request = request[sent:]
                    if not request:
                        sending = False; selector.modify(channel, selectors.EVENT_READ)
                else:
                    data = channel.recv(16384)
                    if not data: break
                    need(len(received) + len(data) <= 96 * 1024, 'API wire budget exceeded')
                    received.extend(data)
            except BlockingIOError:
                continue
    need(time.monotonic() < deadline, 'API aggregate timeout')
    with scope(observer, 'QUERY_RETURN'):
        class OfflineSocket:
            def makefile(self, mode): return io.BytesIO(received)
        response = http.client.HTTPResponse(OfflineSocket()); response.begin()
        if isinstance(observer, Trace): observer.returned(response.status, http=True)
        lengths, transfers = response.headers.get_all('Content-Length', []), response.headers.get_all('Transfer-Encoding', [])
        need(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers) and transfers in ([], ['chunked']), 'API HTTP framing differs')
        need(not lengths or re.fullmatch('[0-9]{1,5}', lengths[0]) and int(lengths[0]) <= 65536, 'API content length differs')
        data = response.read(65537)
        need(len(data) <= 65536 and (not lengths or len(data) == int(lengths[0])) and
             (response.getheader('Content-Type') or '').split(';')[0] == 'application/json', 'bounded API JSON response required')
        result = json.loads(data, object_pairs_hook=unique); status = response.status; response.close()
        return status, result


@observed('QUERY_EXEC')
def request(broker, method, path, body=None):
    observer = getattr(broker, 'observer', None)
    if isinstance(observer, Trace): observer.begin('IMAGE_COMMIT' if method == 'POST' else 'IMAGE_TAG_INSPECT')
    with scope(observer, 'LOCAL_PRE'): broker._local(broker.runner)
    with scope(observer, 'DAEMON_PRE'): broker._info(broker.runner)
    deadline = min(broker.runner.deadline, time.monotonic() + 180)
    with scope(observer, 'QUERY_EXEC'):
        args = (str(broker.socket), method, '/v' + API_VERSION + path, body, deadline)
        status, result = wire(*args, observer=observer) if isinstance(observer, Trace) else wire(*args)
    with scope(observer, 'QUERY_RETURN'):
        if isinstance(observer, Trace): observer.returned(status, http=True)
    with scope(observer, 'LOCAL_POST'): broker._local(broker.runner)
    with scope(observer, 'DAEMON_POST'): broker._info(broker.runner)
    return status, result


@observed('IMAGE_INVENTORY')
def inventory(broker):
    """Capture all current IDs through the broker with a smaller output bound."""
    class InventoryRunner:
        def __getattr__(self, name): return getattr(broker.runner, name)
        def run(self, argv, **kwargs):
            return broker.runner.run(argv, limit=INVENTORY_LIMIT, **kwargs)
    runner = InventoryRunner()
    observer = getattr(broker, 'observer', None)
    if isinstance(observer, Trace): observer.begin('IMAGE_INVENTORY')
    with scope(observer, 'DAEMON_PRE'): broker._info(runner)
    result = broker._raw(['image', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'], runner, timeout=30)
    with scope(observer, 'DAEMON_POST'): broker._info(runner)
    need(result.returncode == 0 and type(result.stdout) is bytes and len(result.stdout) <= INVENTORY_LIMIT,
         'protected image inventory query failed or exceeded bound')
    rows = result.stdout.splitlines(keepends=True)
    need(len(rows) <= MAX_IMAGES and all(re.fullmatch(rb'sha256:[0-9a-f]{64}\n', row) for row in rows),
         'protected image inventory malformed or oversized')
    ids = sorted({row[:-1].decode('ascii') for row in rows})
    need(broker.image in ids, 'accepted base missing from protected inventory')
    return ids


def validate_record(broker, record):
    need(type(record) is dict and set(record) == {'status', 'tag', 'base_image', 'nonce', 'image_id',
         'accepted_config', 'protected_image_ids'} and
         record['status'] in ('COMMIT_ATTEMPTED', 'DERIVED_CONFIG_VERIFIED', 'RECOVERED_FOR_REMOVAL'),
         'owned image journal schema differs')
    need(record['nonce'] == broker.nonce and record['base_image'] == broker.image and
         record['tag'] == 'cachy-asahi-kernel-private:' + broker.nonce and
         (record['image_id'] is None or type(record['image_id']) is str and IMAGE_ID.fullmatch(record['image_id'])) and
         (record['status'] == 'COMMIT_ATTEMPTED' or record['image_id'] is not None), 'owned image journal differs')
    ids = record['protected_image_ids']
    need(type(ids) is list and 1 <= len(ids) <= MAX_IMAGES and
         all(type(value) is str and IMAGE_ID.fullmatch(value) for value in ids) and
         ids == sorted(set(ids)) and broker.image in ids, 'protected image journal differs')
    need(type(record['accepted_config']) is dict and set(record['accepted_config']) == set(FIELDS) and
         record['accepted_config'] == effective(broker.image_config), 'owned image accepted config differs')
    need(len(json.dumps(record, allow_nan=False).encode()) <= INVENTORY_LIMIT, 'owned image journal exceeded bound')


@observed('IMAGE_JOURNAL')
def journal_save(broker, path, record):
    journal_path(path)
    validate_record(broker, record)
    save(path, record)
    descriptor = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def journal_path(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(parent.is_symlink() for parent in (path, *path.parents)), 'owned image journal path differs')
    info = path.parent.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
         'private image journal parent required')


@observed('IMAGE_JOURNAL')
def journal_load(broker, path):
    journal_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size <= INVENTORY_LIMIT,
             'owned image journal file differs')
        data = stream.read(INVENTORY_LIMIT + 1)
        after = os.fstat(stream.fileno())
    need(len(data) <= INVENTORY_LIMIT and (info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
         (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'owned image journal changed during capture')
    record = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False, 'nonfinite owned image journal'))
    validate_record(broker, record)
    return record


def unprotected(record, identifier):
    need(type(identifier) is str and IMAGE_ID.fullmatch(identifier) and
         identifier not in record['protected_image_ids'], 'derived image ID was already protected')


@observed('IMAGE_COMMIT','derive')
def commit(broker, root, journal):
    need(broker.role == 'provision', 'owned provision broker required')
    need(not Path(journal).exists() and not Path(journal).is_symlink(), 'new owned image journal required')
    rows = broker._journal()['containers']
    need(len(rows) == 1 and rows[0]['id'] and rows[0]['name'].endswith('-provision'), 'one exact provision container required')
    identifier = broker._inspect(rows[0]['id'], rows[0])
    tag = 'cachy-asahi-kernel-private:' + broker.nonce
    protected = inventory(broker)
    status, _ = request(broker, 'GET', '/images/' + quote(tag, safe='') + '/json')
    need(status == 404, 'new private image tag required')
    helper = module('kernel_commit_config', Path(root) / 'scripts/ci/commit_image.py')
    payload = helper.commit_config(broker.image_config)
    need(inventory(broker) == protected, 'protected image inventory changed before commit')
    record = {'status': 'COMMIT_ATTEMPTED', 'tag': tag, 'base_image': broker.image, 'nonce': broker.nonce,
              'image_id': None, 'accepted_config': effective(broker.image_config), 'protected_image_ids': protected}
    journal_save(broker, journal, record)  # Directory and file are fsynced before uncertain POST.
    status, result = request(broker, 'POST', '/commit?' + urlencode({'container': identifier, 'pause': 'true',
                           'repo': tag.split(':')[0], 'tag': broker.nonce}), json.dumps(payload).encode())
    need(status == 201 and set(result) == {'Id'} and re.fullmatch(r'sha256:[0-9a-f]{64}', result['Id']), 'immutable derived image response required')
    record['image_id'] = result['Id']; journal_save(broker, journal, record)
    unprotected(record, record['image_id'])
    verify(broker, record)
    record['status'] = 'DERIVED_CONFIG_VERIFIED'; journal_save(broker, journal, record)
    return record


@observed('IMAGE_CONFIG')
def verify(broker, record, cleanup=False, reference=None):
    queried = broker._operation(['image', 'inspect', reference or record['tag']], cleanup=cleanup)
    need(queried.returncode == 0, 'derived image query failed')
    rows = json.loads(queried.stdout)
    base_query = broker._operation(['image', 'inspect', record['base_image']], cleanup=cleanup)
    need(base_query.returncode == 0, 'base image query failed')
    bases = json.loads(base_query.stdout)
    need(len(rows) == len(bases) == 1, 'one exact image required')
    row, base = rows[0], bases[0]
    need(row['Id'] != base['Id'] and row['Architecture'] == 'arm64' and row['Os'] == 'linux' and
         (record['image_id'] is None or row['Id'] == record['image_id']) and
         effective(row['Config']) == record['accepted_config'] == effective(base['Config']), 'derived image config/identity differs')
    original, derived = base['RootFS']['Layers'], row['RootFS']['Layers']
    need(derived[:len(original)] == original and len(derived) == len(original) + 1, 'one derived layer on exact accepted image required')
    need(row['Size'] - base['Size'] <= 3 * 1024**3, 'derived layer size exceeds3GiB budget')
    return row['Id']


@observed('CLEANUP_RESOLVE','cleanup')
def cleanup(broker, journal):
    journal_path(journal)
    if not Path(journal).exists(): return {'status': 'PASS', 'absence_verified': True, 'commit_attempted': False}
    record = journal_load(broker, journal)
    if record['image_id'] is not None: unprotected(record, record['image_id'])
    queried = broker._operation(['image', 'ls', '--no-trunc', '--format', '{{.ID}}', '--filter', 'reference=' + record['tag']], cleanup=True)
    need(queried.returncode == 0, 'owned image absence query failed')
    ids = queried.stdout.decode().splitlines()
    need(len(ids) <= 1 and all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) and value != broker.image for value in ids), 'owned image query differs')
    if not ids and record['image_id'] is None:
        # A timed-out POST can still complete after these queries. Without a
        # recovered immutable ID, an empty tag list proves only current absence.
        observer = getattr(broker, 'observer', None)
        if isinstance(observer, Trace): observer.fail(RuntimeError(), 'UNCERTAIN_MUTATION')
        return {'status': 'FAIL', 'absence_verified': False, 'commit_attempted': True,
                'uncertain_commit': True}
    if ids:
        unprotected(record, ids[0])
        identifier = verify(broker, record, cleanup=True)
        need(identifier == ids[0], 'owned image identity differs')
        if record['image_id'] is None:
            # Persist recovered ownership before deletion; a subsequent failure
            # can retry by ID even after removal of the private tag.
            record.update(image_id=identifier, status='RECOVERED_FOR_REMOVAL')
            journal_save(broker, journal, record)
        unprotected(record, identifier)
        removed = broker._operation(['image', 'rm', '--no-prune', record['tag']], cleanup=True)
        need(removed.returncode == 0, 'owned image removal failed')
    checked = broker._operation(['image', 'ls', '--no-trunc', '--format', '{{.ID}}', '--filter', 'reference=' + record['tag']], cleanup=True)
    need(checked.returncode == 0 and checked.stdout == b'', 'owned private tag still present')
    if record['image_id'] is not None:
        remaining = broker._operation(['image', 'inspect', record['image_id']], cleanup=True)
        if remaining.returncode == 0:
            verify(broker, record, cleanup=True, reference=record['image_id'])
            unprotected(record, record['image_id'])
            removed = broker._operation(['image', 'rm', '--no-prune', record['image_id']], cleanup=True)
            need(removed.returncode == 0, 'owned image ID removal failed')
            remaining = broker._operation(['image', 'inspect', record['image_id']], cleanup=True)
        need(remaining.returncode != 0 and b'No such image' in remaining.stdout, 'owned image ID absence unverified')
    return {'status': 'PASS', 'absence_verified': True, 'commit_attempted': True}
