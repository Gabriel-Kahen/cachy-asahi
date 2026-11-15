#!/usr/bin/env python3
"""Finite primary-file fetch, retaining predecessor accounting mechanics."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import signal
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
MAX_REQUESTS, TOTAL_BYTES, ONE_BODY = 50, 2 * 1024**2, 128 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def acquire(url, filename):
    ledger = HERE / 'requests.json'
    history = json.loads(ledger.read_text()) if ledger.exists() else {'requests': [], 'body_bytes': 0, 'started_epoch': time.time()}
    if history.get('acquisition_closed') or time.time() - history['started_epoch'] >= 900:
        raise ValueError('finite acquisition closed or 900second window exhausted')
    signal.alarm(max(1, int(900 - (time.time() - history['started_epoch']))))
    if Path(filename).name != filename:
        raise ValueError('plain new evidence filename required')
    output = HERE / 'evidence' / filename
    if output.exists():
        raise ValueError('new output required; do not retry retained requests')
    opener = urllib.request.build_opener(NoRedirect)
    for _ in range(3):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.hostname not in {'api.github.com', 'raw.githubusercontent.com', 'github.com'} or parsed.username or parsed.password:
            raise ValueError('primary HTTPS GitHub source endpoints only')
        if len(history['requests']) >= MAX_REQUESTS:
            raise ValueError('50request budget exhausted')
        event = {'ordinal': len(history['requests']) + 1, 'url': url, 'bytes': 0, 'complete_body': False}
        history['requests'].append(event)
        ledger.write_text(json.dumps(history, indent=2, sort_keys=True) + '\n')
        started = time.monotonic()
        response = None
        body = bytearray()
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'bounded-primary-notice-successor-e', 'Accept': 'application/vnd.github+json' if parsed.hostname == 'api.github.com' else '*/*'})
            try:
                response = opener.open(request, timeout=20)
            except urllib.error.HTTPError as failure:
                response = failure
            event['HTTP'] = response.code
            while True:
                if time.monotonic() - started > 60:
                    raise TimeoutError('60second file transfer deadline')
                remaining = min(ONE_BODY - len(body), TOTAL_BYTES - history['body_bytes'])
                if remaining <= 0:
                    raise ValueError('per-file or aggregate body cap reached before EOF')
                part = response.read(min(65536, remaining))
                if not part:
                    break
                body.extend(part)
                event['bytes'] += len(part)
                history['body_bytes'] += len(part)
            event.update({'sha256': hashlib.sha256(body).hexdigest(), 'complete_body': True})
            location = response.headers.get('Location')
            if response.code in (301, 302, 303, 307, 308) and location:
                event['location'] = urllib.parse.urljoin(url, location)
                url = event['location']
            else:
                output.write_bytes(body)
                event['file'] = filename
                return event
        except BaseException as error:
            event.update({'error': type(error).__name__ + ': ' + str(error), 'received_prefix_sha256': hashlib.sha256(body).hexdigest()})
            raise
        finally:
            if response is not None:
                response.close()
            event['seconds'] = round(time.monotonic() - started, 3)
            ledger.write_text(json.dumps(history, indent=2, sort_keys=True) + '\n')
    raise ValueError('redirect limit reached')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('url')
    parser.add_argument('filename')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    print(json.dumps(acquire(args.url, args.filename), sort_keys=True))
