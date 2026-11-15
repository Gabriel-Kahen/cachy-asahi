#!/usr/bin/env python3
"""Bounded primary-file acquisition, reusing the preceding finite fetcher."""
import importlib.util
import json
from pathlib import Path
import resource
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prior_fetch', HERE.parent.parent / 'fetch.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.MAX_REQUESTS, prior.TOTAL_BYTES, prior.ONE_BODY = 20, 16 * 1024**2, 2 * 1024**2


def acquire(url, filename):
    ledger = HERE / 'requests.json'
    if not ledger.exists():
        ledger.write_text(json.dumps({'requests': [], 'body_bytes': 0, 'started_epoch': time.time()}))
    history = json.loads(ledger.read_text())
    if history.get('acquisition_closed'):
        raise ValueError('finite acquisition is closed; replay retained evidence')
    start = history['started_epoch']
    if time.time() - start >= 900:
        raise ValueError('900second acquisition window exhausted')
    signal.alarm(max(1, int(900 - (time.time() - start))))
    if Path(filename).name != filename:
        raise ValueError('plain new evidence filename required')
    try:
        return prior.fetch(url, HERE / 'evidence' / filename, ledger)
    except BaseException as error:
        history = json.loads(ledger.read_text())
        if history['requests'] and 'file' not in history['requests'][-1]:
            history['requests'][-1].update({'error': type(error).__name__ + ': ' + str(error), 'body_not_retained': True})
            ledger.write_text(json.dumps(history, indent=2, sort_keys=True) + '\n')
        raise


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    print(json.dumps(acquire(*sys.argv[1:]), sort_keys=True))
