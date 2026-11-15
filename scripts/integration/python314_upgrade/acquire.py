#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Acquire exactly one historical Arch Python package/signature pair; no fallback."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import urllib.request

BASELINE = 'python-3.14.7-1-x86_64.pkg.tar.zst'
PINS = {BASELINE: {'bytes': 14184166, 'sha256': '8a350ce53aae01ae687f043b301931e411bf06333ba480b42b3b5432a0e6c79b'},
        BASELINE + '.sig': {'bytes': 310, 'sha256': 'ff4000fab52654e77a2de73ff242ea809b0b4fd2e17951a8375f575180c1ecae'}}
PREFIX = 'https://archive.archlinux.org/packages/p/python/'


def verify(directory):
    for name, pin in PINS.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != pin['bytes']:
            raise ValueError('exact historical baseline material missing: ' + name)
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != pin['sha256']:
                raise ValueError('historical baseline bytes changed: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('fresh ordinary private output required')
    output.mkdir(mode=0o700)
    report = {'schema_version': 1, 'status': 'HOLD', 'package': 'python3.14.7-1/x86_64', 'requests': [],
              'signature_acceptance': 'NOT YET VERIFIED; disposable public Arch keyring gate required',
              'fallbacks': 'NONE; no other version, architecture, repository or trust permitted'}
    def deadline(signum, frame):
        raise TimeoutError('140-second acquisition deadline')
    old = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(140)
    try:
        for name, pin in PINS.items():
            url = PREFIX + name
            row = {'url': url}
            report['requests'].append(row)
            with urllib.request.urlopen(url, timeout=45) as response:
                row.update(http_status=response.status, effective_url=response.url)
                if response.status != 200 or response.url != url:
                    raise ValueError('exact official endpoint required')
                total = 0
                with (output / name).open('xb') as stream:
                    while chunk := response.read(65536):
                        total += len(chunk)
                        if total > pin['bytes']:
                            raise ValueError('historical material exceeds exact size bound')
                        stream.write(chunk)
            row.update(pin)
        verify(output)
        report['status'] = 'PASS exact official bytes acquired; public signature gate remains mandatory'
    except Exception as exc:
        report['blocker'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
        (output / 'acquisition.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'report': str(output / 'acquisition.json')}))
    return 0 if report['status'].startswith('PASS') else 2


if __name__ == '__main__':
    raise SystemExit(main())
