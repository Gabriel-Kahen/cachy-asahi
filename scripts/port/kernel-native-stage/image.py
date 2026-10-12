#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One nonce-owned derived image, committed with the accepted base config."""
import http.client
import errno
import io
import json
from pathlib import Path
import re
import socket
import selectors
import time
from urllib.parse import quote, urlencode

from common import load, module, need, save, unique

FIELDS = ('User', 'Env', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels', 'Volumes', 'ExposedPorts',
          'StopSignal', 'Shell', 'Healthcheck', 'ArgsEscaped')


def effective(config):
    value = {key: config.get(key) for key in FIELDS}
    if value['Entrypoint'] in (None, [], ['']): value['Entrypoint'] = None
    if value['Cmd'] in (None, []): value['Cmd'] = None
    return value


def wire(path, method, target, body, deadline):
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
    class OfflineSocket:
        def makefile(self, mode): return io.BytesIO(received)
    response = http.client.HTTPResponse(OfflineSocket()); response.begin()
    lengths, transfers = response.headers.get_all('Content-Length', []), response.headers.get_all('Transfer-Encoding', [])
    need(len(lengths) <= 1 and len(transfers) <= 1 and not (lengths and transfers) and transfers in ([], ['chunked']), 'API HTTP framing differs')
    need(not lengths or re.fullmatch('[0-9]{1,5}', lengths[0]) and int(lengths[0]) <= 65536, 'API content length differs')
    data = response.read(65537)
    need(len(data) <= 65536 and (not lengths or len(data) == int(lengths[0])) and
         (response.getheader('Content-Type') or '').split(';')[0] == 'application/json', 'bounded API JSON response required')
    result = json.loads(data, object_pairs_hook=unique); status = response.status; response.close()
    return status, result


def request(broker, method, path, body=None):
    broker._local(broker.runner); broker._info(broker.runner)
    deadline = min(broker.runner.deadline, time.monotonic() + 180)
    status, result = wire(str(broker.socket), method, '/v1.49' + path, body, deadline)
    broker._local(broker.runner); broker._info(broker.runner)
    return status, result


def commit(broker, root, journal):
    need(broker.role == 'provision', 'owned provision broker required')
    rows = broker._journal()['containers']
    need(len(rows) == 1 and rows[0]['id'] and rows[0]['name'].endswith('-provision'), 'one exact provision container required')
    identifier = broker._inspect(rows[0]['id'], rows[0])
    tag = 'cachy-asahi-kernel-private:' + broker.nonce
    status, _ = request(broker, 'GET', '/images/' + quote(tag, safe='') + '/json')
    need(status == 404, 'new private image tag required')
    helper = module('kernel_commit_config', Path(root) / 'scripts/ci/commit_image.py')
    payload = helper.commit_config(broker.image_config)
    record = {'status': 'COMMIT_ATTEMPTED', 'tag': tag, 'base_image': broker.image, 'nonce': broker.nonce,
              'image_id': None, 'accepted_config': effective(broker.image_config)}
    save(journal, record)  # Retain ownership before a potentially uncertain POST.
    status, result = request(broker, 'POST', '/commit?' + urlencode({'container': identifier, 'pause': 'true',
                           'repo': tag.split(':')[0], 'tag': broker.nonce}), json.dumps(payload).encode())
    need(status == 201 and set(result) == {'Id'} and re.fullmatch(r'sha256:[0-9a-f]{64}', result['Id']), 'immutable derived image response required')
    record['image_id'] = result['Id']; save(journal, record)
    verify(broker, record)
    record['status'] = 'DERIVED_CONFIG_VERIFIED'; save(journal, record)
    return record


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


def cleanup(broker, journal):
    if not Path(journal).exists(): return {'status': 'PASS', 'absence_verified': True, 'commit_attempted': False}
    record = load(journal)
    need(record['nonce'] == broker.nonce and record['base_image'] == broker.image and
         record['tag'] == 'cachy-asahi-kernel-private:' + broker.nonce, 'owned image journal differs')
    queried = broker._operation(['image', 'ls', '--no-trunc', '--format', '{{.ID}}', '--filter', 'reference=' + record['tag']], cleanup=True)
    need(queried.returncode == 0, 'owned image absence query failed')
    ids = queried.stdout.decode().splitlines()
    need(len(ids) <= 1 and all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) and value != broker.image for value in ids), 'owned image query differs')
    if not ids and record['image_id'] is None:
        # A timed-out POST can still complete after these queries. Without a
        # recovered immutable ID, an empty tag list proves only current absence.
        return {'status': 'FAIL', 'absence_verified': False, 'commit_attempted': True,
                'uncertain_commit': True}
    if ids:
        identifier = verify(broker, record, cleanup=True)
        need(identifier == ids[0], 'owned image identity differs')
        if record['image_id'] is None:
            # Persist recovered ownership before deletion; a subsequent failure
            # can retry by ID even after removal of the private tag.
            record.update(image_id=identifier, status='RECOVERED_FOR_REMOVAL')
            save(journal, record)
        removed = broker._operation(['image', 'rm', record['tag']], cleanup=True)
        need(removed.returncode == 0, 'owned image removal failed')
    checked = broker._operation(['image', 'ls', '--no-trunc', '--format', '{{.ID}}', '--filter', 'reference=' + record['tag']], cleanup=True)
    need(checked.returncode == 0 and checked.stdout == b'', 'owned private tag still present')
    if record['image_id'] is not None:
        remaining = broker._operation(['image', 'inspect', record['image_id']], cleanup=True)
        if remaining.returncode == 0:
            verify(broker, record, cleanup=True, reference=record['image_id'])
            removed = broker._operation(['image', 'rm', record['image_id']], cleanup=True)
            need(removed.returncode == 0, 'owned image ID removal failed')
            remaining = broker._operation(['image', 'inspect', record['image_id']], cleanup=True)
        need(remaining.returncode != 0 and b'No such image' in remaining.stdout, 'owned image ID absence unverified')
    return {'status': 'PASS', 'absence_verified': True, 'commit_attempted': True}
