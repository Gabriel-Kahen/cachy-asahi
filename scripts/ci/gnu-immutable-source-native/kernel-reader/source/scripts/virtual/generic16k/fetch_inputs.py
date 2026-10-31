#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the finite input manifest; fetch only with explicit --fetch."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import signal
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
EXPECTED = [
    {'name': 'kernel', 'filename': 'kernel.tar.gz',
     'url': 'https://github.com/AsahiLinux/linux/archive/asahi-7.1.13-3.tar.gz',
     'bytes': 262965559, 'sha256': '874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',
     'allowed_hosts': ['github.com', 'codeload.github.com'],
     'source_evidence': 'artifacts/platform/kernel-history-20261012/kernel-source-archive.json',
     'source_revision': '94fb23346d522edf53722357c426a3e58030beea'},
    {'name': 'rootfs', 'filename': 'rootfs.tar.gz',
     'url': 'https://ca.us.mirror.archlinuxarm.org/os/multi/ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz',
     'bytes': 829367415, 'sha256': '42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319',
     'allowed_hosts': ['ca.us.mirror.archlinuxarm.org'],
     'source_evidence': 'scripts/ci/maintained-desktop574-inputs.json#rootfs',
     'source_revision': 'ArchLinuxARM-2026.08-aarch64-rootfs'}]


def no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise ValueError('duplicate manifest key')
        d[k] = v
    return d


def load_manifest(path):
    with Path(path).open('rb') as stream: raw = stream.read(16385)
    if len(raw) > 16384: raise ValueError('manifest size budget')
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    # Type equality is explicit: JSON true/1.0 must not alias integer pins.
    if (not isinstance(value, dict) or set(value) != {'schema', 'inputs'}
            or type(value['schema']) is not int or value['schema'] != 1
            or not isinstance(value['inputs'], list) or len(value['inputs']) != 2):
        raise ValueError('manifest schema')
    for item, expected in zip(value['inputs'], EXPECTED):
        if not isinstance(item, dict) or item != expected or type(item.get('bytes')) is not int:
            raise ValueError('manifest must match exact finite input pins')
    return value, hashlib.sha256(raw).hexdigest()


def allowed(url, hosts):
    p = urllib.parse.urlsplit(url)
    if (p.scheme != 'https' or p.hostname not in hosts or p.username is not None
            or p.password is not None or p.port is not None or p.fragment):
        raise ValueError('undeclared HTTPS origin')
    return url


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts; self.seen = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed(newurl, self.hosts)
        if len(self.seen) >= 5: raise ValueError('redirect budget')
        self.seen.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@contextmanager
def deadline_alarm(seconds):
    """Standalone Linux caller hard bound, including DNS/TLS/slow response reads."""
    previous = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0): raise ValueError('caller already has an active deadline')
    def expired(signum, frame): raise TimeoutError('total fetch deadline')
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def fetch_one(item, out, deadline, opener=None):
    redirects = Redirects(item['allowed_hosts'])
    if opener is None:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), redirects)
    requested = allowed(item['url'], item['allowed_hosts'])
    request = urllib.request.Request(requested, headers={'Accept-Encoding': 'identity',
                                                        'User-Agent': 'cachy-asahi-16k-input-fetch/1'})
    partial = out/(item['filename']+'.partial'); final = out/item['filename']
    h = hashlib.sha256(); count = 0; created = False
    try:
        if final.exists() or final.is_symlink(): raise ValueError('destination exists')
        with partial.open('xb') as dst:
            created = True
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('total fetch deadline')
            with opener.open(request, timeout=min(30, remaining)) as response:
                final_url = allowed(response.geturl(), item['allowed_hosts'])
                if response.status != 200: raise ValueError('HTTP status must be 200')
                length = response.headers.get('Content-Length')
                if length is not None and length != str(item['bytes']): raise ValueError('declared length mismatch')
                if response.headers.get('Content-Encoding', 'identity') != 'identity': raise ValueError('encoded content')
                while True:
                    if time.monotonic() >= deadline: raise TimeoutError('total fetch deadline')
                    chunk = response.read1(min(1 << 20, item['bytes']-count+1))
                    if not chunk: break
                    count += len(chunk)
                    if count > item['bytes']: raise ValueError('input byte budget')
                    dst.write(chunk); h.update(chunk)
        if count != item['bytes'] or h.hexdigest() != item['sha256']: raise ValueError('input length/hash mismatch')
        partial.rename(final)
        return {'name': item['name'], 'path': str(final), 'requested_url': requested,
                'final_url': final_url, 'redirects': redirects.seen, 'bytes': count,
                'sha256': h.hexdigest(), 'attempts': 1, 'source_evidence': item['source_evidence'],
                'source_revision': item['source_revision'],
                'authentication': 'HTTPS plus exact historical SHA256 pin; no fresh signature verification'}
    finally:
        # Only this helper's fixed-name partial is created in the new owned directory.
        if created and partial.exists(): partial.unlink()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', default=str(HERE/'inputs.json'))
    p.add_argument('--fetch', action='store_true')
    p.add_argument('--out')
    a = p.parse_args(); manifest, manifest_sha = load_manifest(a.manifest)
    if not a.fetch:
        print(json.dumps({'status': 'VALIDATED_NOT_FETCHED', 'manifest_sha256': manifest_sha,
                          'inputs': manifest['inputs']}, indent=2)); return
    if not a.out: p.error('--fetch requires --out NEW_DIRECTORY')
    out = Path(a.out).absolute(); out.mkdir(mode=0o700)
    result = {'status': 'FAIL', 'manifest_sha256': manifest_sha, 'inputs': [],
              'total_deadline_seconds': 300, 'attempts_per_input': 1,
              'guest_execution': 'NOT RUN', 'package_actors': 'NOT RUN'}
    try:
        with deadline_alarm(300):
            deadline = time.monotonic()+300
            for item in manifest['inputs']: result['inputs'].append(fetch_one(item, out, deadline))
        result['status'] = 'FETCHED_HASH_VERIFIED'
    except BaseException as e:
        result['error'] = type(e).__name__+': '+str(e); raise
    finally:
        result['partial_files_absent'] = all(not (out/(i['filename']+'.partial')).exists() for i in manifest['inputs'])
        with (out/'fetch-result.json').open('x') as f: f.write(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    def terminate(signum, frame): raise KeyboardInterrupt('termination signal')
    signal.signal(signal.SIGTERM, terminate)
    main()
