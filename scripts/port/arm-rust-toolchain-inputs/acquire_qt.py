#!/usr/bin/env python3
"""Acquire only the reviewed frozen Qt inputs; inspect data, never install."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('catalog', HERE / 'catalog.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def tmp_path(path):
    result = path.resolve()
    c.require(Path('/tmp') in result.parents and not path.is_symlink(), 'output/cache must be below /tmp')
    return result


def cache_bytes(cache):
    total = 0
    for path in cache.iterdir():
        c.require(path.is_file() and not path.is_symlink(), 'nonregular cache input')
        if path.name.endswith('.pkg.tar.xz'):
            total += path.stat().st_size
    return total


def fetch(cache, filename, expected, routes, ceiling, blocked_hosts, events):
    target = cache / filename
    if target.exists() or target.is_symlink():
        c.pin(target, expected)
        events.append({'filename': filename, 'result': 'EXACT_RETAINED_BYTES'})
        return target
    c.require(expected['bytes'] <= 32 * 1024 * 1024, 'single input exceeds finite bound')
    c.require(cache_bytes(cache) + (expected['bytes'] if filename.endswith('.xz') else 0) <= ceiling,
              'archive cache would exceed512MiB')
    for url in routes:
        host = urllib.parse.urlsplit(url).hostname
        if host in blocked_hosts:
            events.append({'url': url, 'result': 'SKIPPED_AFTER_HTTP429_AVAILABILITY_UNKNOWN'})
            continue
        deadline = time.monotonic() + 60
        try:
            with urllib.request.urlopen(url, timeout=20) as response:
                c.require(response.url == url, 'unreviewed redirect')
                with tempfile.TemporaryDirectory(prefix='qt-transfer-', dir=cache.parent) as temporary:
                    partial = Path(temporary) / filename
                    count = 0
                    with partial.open('xb') as out:
                        while chunk := response.read(min(1024 * 1024, expected['bytes'] + 1 - count)):
                            count += len(chunk)
                            c.require(count <= expected['bytes'] and time.monotonic() < deadline,
                                      'transfer exceeds byte/time bound')
                            out.write(chunk)
                    partial.chmod(0o600)
                    c.pin(partial, expected)
                    c.require(not target.exists(), 'cache changed during transfer')
                    partial.rename(target)
            events.append({'url': url, 'result': 'EXACT_ACQUIRED_BYTES', 'descriptor': expected})
            return target
        except urllib.error.HTTPError as error:
            if error.code == 429:
                blocked_hosts.add(host)
            events.append({'url': url, 'HTTP': error.code, 'availability': 'UNKNOWN' if error.code == 429 else 'NOT_SERVED'})
        except (urllib.error.URLError, TimeoutError) as error:
            events.append({'url': url, 'availability': 'UNKNOWN', 'transport_error': str(error)})
    return None


def metadata(archive):
    with tarfile.open(archive, mode='r|*') as stream:
        for member in stream:
            if member.name == '.PKGINFO':
                c.require(member.isfile() and member.size <= 1024 * 1024, 'invalid PKGINFO')
                with stream.extractfile(member) as data:
                    return c.fields(data.read())
    raise ValueError('PKGINFO missing')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory below /tmp')
    parser.add_argument('--retained-cache', type=Path, action='append', default=[], help='read-only exact-file cache')
    args = parser.parse_args()
    cache, output = tmp_path(args.cache), tmp_path(args.output)
    c.require(cache != output and cache not in output.parents and output not in cache.parents, 'overlapping paths')
    c.require(not output.exists(), 'output exists')
    space = os.statvfs('/tmp')
    available = next(int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    free = space.f_bavail * space.f_frsize
    c.require(free >= 1024 * 1024 * 1024 and available >= 512 * 1024 * 1024, 'insufficient fresh space/RAM')
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.chmod(0o700)
    output.mkdir(mode=0o700, parents=True)
    lock = json.loads((HERE / 'inputs.lock.json').read_text())
    c.pin(HERE / 'qt-frozen-inputs.json', lock['qt_frozen_inputs'])
    data = (HERE / 'qt-frozen-inputs.json').read_bytes()
    frozen = json.loads(data)
    c.require(frozen['keyring'] == lock['public_keyring'] and frozen['signer_primary'] == lock['signer_primary'],
              'Qt source/key binding changed')
    c.require(cache_bytes(cache) <= frozen['maximum_archive_cache_bytes'], 'cache already exceeds limit')
    c.pin(HERE / 'alarm-public.gpg', frozen['keyring'])
    c.snapshot(HERE / 'alarm-public.gpg', output / 'alarm-public.gpg', frozen['keyring'], time.monotonic() + 10)
    (output / 'qt-frozen-inputs.json').write_bytes(data)
    events, blocked, results = [], set(), {}
    for name, record in frozen['packages'].items():
        filename = record['filename']
        for suffix, expected in [('', record['archive']), ('.sig', record['signature'])]:
            retained = c.find_input(filename + suffix, args.retained_cache, expected)
            target = cache / (filename + suffix)
            if retained is not None and not target.exists():
                c.require(cache_bytes(cache) + (expected['bytes'] if not suffix else 0) <= frozen['maximum_archive_cache_bytes'],
                          'retained copy exceeds512MiB archive limit')
                c.snapshot(retained, target, expected, time.monotonic() + 30)
                events.append({'filename': target.name, 'result': 'EXACT_RETAINED_BYTES_SNAPSHOTTED', 'source': str(retained)})
        archive = fetch(cache, filename, record['archive'], record['routes'],
                        frozen['maximum_archive_cache_bytes'], blocked, events)
        signature = fetch(cache, filename + '.sig', record['signature'], [u + '.sig' for u in record['routes']],
                          frozen['maximum_archive_cache_bytes'], blocked, events)
        if archive is None or signature is None:
            results[name] = {'status': 'MISSING_EXACT_INPUT', 'archive_missing': archive is None,
                             'signature_missing': signature is None}
        else:
            with tempfile.TemporaryDirectory(prefix='qt-verified-', dir=output) as temporary:
                a, s = Path(temporary) / filename, Path(temporary) / (filename + '.sig')
                c.snapshot(archive, a, record['archive'], time.monotonic() + 30)
                c.snapshot(signature, s, record['signature'], time.monotonic() + 10)
                math = c.signatures(a, s, output / 'alarm-public.gpg', frozen['signer_primary'])
                info = metadata(a)
                package = dict(record, name=name, depends=info.get('depend', []), provides=info.get('provides', []))
                inspection = c.inspect_archive(a, package, time.monotonic() + 180)
            results[name] = {'status': 'VERIFIED_ARCHIVE_DATA', 'signature': math, 'actual_pkginfo': info,
                             'inspection': inspection}
        # Retain progress even if a later input refuses.
        receipt = {'schema': 1, 'frozen_inputs': c.digest(data), 'resource_preflight': {'tmp_available_bytes': free,
                   'MemAvailable_bytes': available}, 'archive_cache_bytes': cache_bytes(cache), 'events': events,
                   'packages': results, 'native_execution': 'NOT_RUN', 'source_legal_freshness_acceptance': 'HELD'}
        (output / 'acquisition.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'verified': [n for n, r in results.items() if r['status'] == 'VERIFIED_ARCHIVE_DATA'],
                      'missing': [n for n, r in results.items() if r['status'] != 'VERIFIED_ARCHIVE_DATA'],
                      'archive_cache_bytes': cache_bytes(cache)}, sort_keys=True))
    return 0 if all(r['status'] == 'VERIFIED_ARCHIVE_DATA' for r in results.values()) else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, tarfile.TarError) as error:
        raise SystemExit(f'REFUSED: {error}')
