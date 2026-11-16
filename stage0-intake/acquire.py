#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One-attempt, pinned stage0 HTTPS intake; retains opaque bytes, never executes them."""
import datetime
import hashlib
import http.client
import json
from pathlib import Path
import resource
import shutil
import signal
import ssl
import time
from urllib.parse import urljoin, urlsplit

HERE = Path(__file__).resolve().parent
WORK = HERE / 'work'
LIMIT = 300 * 1024**2
MIN_FREE = 1024**3
resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))


def save(path, value):
    temp = path.with_suffix(path.suffix + '.new')
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temp.replace(path)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def acquire():
    WORK.mkdir(exist_ok=True)
    artifacts = WORK / 'artifacts'
    artifacts.mkdir(exist_ok=True)
    state_path = HERE / 'acquisition.json'
    if state_path.exists():
        raise ValueError('intake already attempted; no automatic retry or reset')
    pins = json.loads((HERE.parent / 'inputs.json').read_bytes())
    selected = {k: v for k, v in pins['archives'].items() if v['role'] == 'stage0'}
    search = json.loads((HERE / 'retained-search.json').read_bytes())
    state = {'schema': 1, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'RUNNING', 'limits': {'HTTPS_requests_including_redirects': 8, 'response_body_bytes': LIMIT, 'address_space_bytes': 512 * 1024**2, 'seconds': 1200, 'minimum_available_storage_bytes': MIN_FREE}, 'requests': [], 'artifacts': {}, 'publisher_execution': 0, 'TLS_verification': 'ssl.create_default_context; CERT_REQUIRED; hostname checking enabled'}
    save(state_path, state)
    started = time.monotonic()
    def timeout(_signum, _frame):
        raise TimeoutError('1200-second intake deadline reached')
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(1200)
    def guard():
        if time.monotonic() - started > 1200:
            raise ValueError('1200-second deadline exceeded')
        if shutil.disk_usage(WORK).free < MIN_FREE:
            raise ValueError('available storage below 1 GiB')
        if sum(r['body_bytes'] for r in state['requests']) > LIMIT:
            raise ValueError('cumulative body budget exceeded')
    try:
        for name, pin in selected.items():
            guard()
            retained = [Path(p) for p in search['matching_paths'] if Path(p).name == name]
            retained = [p for p in retained if p.is_file() and digest(p) == pin['sha256']]
            if retained:
                path = retained[0].resolve()
                state['artifacts'][name] = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': pin['sha256'], 'origin': 'REUSED_EXACT_RETAINED_BYTES'}
                save(state_path, state)
                continue
            destination = artifacts / name
            partial = destination.with_suffix(destination.suffix + '.partial')
            if destination.exists() or partial.exists():
                raise ValueError('existing private output; refuse duplicate transfer')
            url = pin['url']
            while True:
                guard()
                if len(state['requests']) >= 8:
                    raise ValueError('request/redirect limit reached')
                parsed = urlsplit(url)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in [None, 443]:
                    raise ValueError('nonstandard/non-TLS redirect refused')
                record = {'url': url, 'body_bytes': 0, 'status': 'ATTEMPTED', 'method': 'GET'}
                state['requests'].append(record)
                save(state_path, state)  # intent before connection; failed requests count
                context = ssl.create_default_context()
                connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=min(30, max(1, 1200 - (time.monotonic() - started))), context=context)
                try:
                    connection.request('GET', parsed.path + ('?' + parsed.query if parsed.query else ''), headers={'Accept-Encoding': 'identity', 'User-Agent': 'Cachy-Asahi-pinned-stage0-data-intake/1'})
                    response = connection.getresponse()
                    record['http_status'] = response.status
                    record['content_length'] = response.getheader('Content-Length')
                    remaining = LIMIT - sum(r['body_bytes'] for r in state['requests'])
                    if record['content_length'] and int(record['content_length']) > remaining:
                        raise ValueError('declared body exceeds remaining cumulative limit')
                    redirect = response.status in [301, 302, 303, 307, 308]
                    location = response.getheader('Location')
                    if response.status != 200 and not redirect:
                        raise ValueError(f'HTTP {response.status}; no retry')
                    h = hashlib.sha256()
                    stream = partial.open('xb') if response.status == 200 else None
                    try:
                        while True:
                            guard()
                            remaining = LIMIT - sum(r['body_bytes'] for r in state['requests'])
                            if remaining == 0:
                                if response.length == 0:
                                    break
                                raise ValueError('body budget exhausted; no additional read')
                            connection.sock.settimeout(min(30, max(0.01, 1200 - (time.monotonic() - started))))
                            chunk = response.read(min(1024**2, remaining))
                            if not chunk:
                                break
                            record['body_bytes'] += len(chunk)
                            if len(chunk) > remaining:
                                raise ValueError('body budget exceeded; excess byte not retained')
                            h.update(chunk)
                            if stream:
                                stream.write(chunk)
                            save(state_path, state)
                    finally:
                        if stream:
                            stream.close()
                    record['body_sha256'] = h.hexdigest()
                    record['status'] = 'RECEIVED'
                    save(state_path, state)
                    if redirect:
                        if not location:
                            raise ValueError('redirect without location')
                        url = urljoin(url, location)
                        continue
                    if h.hexdigest() != pin['sha256']:
                        raise ValueError('whole archive SHA-256 mismatch')
                    partial.replace(destination)
                    state['artifacts'][name] = {'path': str(destination), 'bytes': destination.stat().st_size, 'sha256': h.hexdigest(), 'origin': 'FETCHED_ONCE_TLS_PIN_MATCH', 'final_url': url}
                    save(state_path, state)
                    print(f'{name}: {destination.stat().st_size} bytes, pinned SHA-256 PASS', flush=True)
                    break
                finally:
                    connection.close()
        state['status'] = 'THREE_EXACT_ARCHIVES_RETAINED_DATA_ONLY'
    except Exception as error:
        state['status'] = 'STOPPED_NO_RETRY'
        state['error'] = str(error)
        raise
    finally:
        state['elapsed_seconds'] = round(time.monotonic() - started, 3)
        state['response_body_bytes'] = sum(r['body_bytes'] for r in state['requests'])
        state['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        state['available_storage_bytes_at_end'] = shutil.disk_usage(WORK).free
        save(state_path, state)


if __name__ == '__main__':
    acquire()
